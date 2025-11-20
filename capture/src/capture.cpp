#ifdef _WIN32
#  include <windows.h>
#  include <io.h>
#else
#  include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <clamp>         // C++20 header; if unavailable use algorithm
#include <cinttypes>
#include <mutex>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <memory>

#include "../../public/common/TracyProtocol.hpp"
#include "../../public/common/TracyStackFrames.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyMemory.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracySysUtil.hpp"
#include "../../server/TracyWorker.hpp"

#ifdef _WIN32
#  include "../../getopt/getopt.h"
#endif

// ---------- Notes on changes ----------
/*
 - Use std::string_view for readonly string parameters.
 - Use std::lock_guard (RAII) instead of manual lock/unlock.
 - Avoid small fixed-size format buffer in AnsiPrintf: allocate dynamic buffer sized via vsnprintf.
 - Cache calls that don't need to be repeated every loop iteration (IsStdoutATerminal).
 - Use constexpr for constants and centralize ANSI codes as string_view.
 - Use std::this_thread::sleep_for with a named constant.
 - Keep signal handling behavior intact but minimize what handler does (only atomic store).
*/

// Atomic used by signal handler
static std::atomic<bool> s_disconnect { false };

void SigInt( int )
{
    s_disconnect.store(true, std::memory_order_relaxed);
}

static std::atomic<bool> s_isStdoutATerminal { false };

void InitIsStdoutATerminal() {
#ifdef _WIN32
    s_isStdoutATerminal.store( _isatty( fileno( stdout ) ) != 0, std::memory_order_relaxed );
#else
    s_isStdoutATerminal.store( isatty( fileno( stdout ) ) != 0, std::memory_order_relaxed );
#endif
}

inline bool IsStdoutATerminal() noexcept { return s_isStdoutATerminal.load(std::memory_order_relaxed); }

// ANSI codes as constexpr string_view for efficiency
constexpr std::string_view ANSI_RESET      = "\033[0m";
constexpr std::string_view ANSI_BOLD       = "\033[1m";
constexpr std::string_view ANSI_BLACK      = "\033[30m";
constexpr std::string_view ANSI_RED        = "\033[31m";
constexpr std::string_view ANSI_GREEN      = "\033[32m";
constexpr std::string_view ANSI_YELLOW     = "\033[33m";
constexpr std::string_view ANSI_BLUE       = "\033[34m";
constexpr std::string_view ANSI_MAGENTA    = "\033[35m";
constexpr std::string_view ANSI_CYAN       = "\033[36m";
constexpr std::string_view ANSI_ERASE_LINE = "\033[2K";

// Safe, terminal-aware printf with dynamic buffer allocation to avoid truncation.
// If stdout is a TTY, wraps with ansiEscape and ANSI_RESET.
void AnsiPrintf( std::string_view ansiEscape, const char* format, ... ) {
    va_list args;
    va_start(args, format);
    if( IsStdoutATerminal() )
    {
        // Compute required size
        va_list args_copy;
        va_copy(args_copy, args);
        const int needed = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);
        if( needed < 0 )
        {
            va_end(args);
            return;
        }
        std::vector<char> buf(static_cast<size_t>(needed) + 1);
        vsnprintf(buf.data(), buf.size(), format, args);
        va_end(args);
        // Print wrapped string in one call to avoid interleaving.
        printf("%.*s%s%s", (int)ansiEscape.size(), ansiEscape.data(), buf.data(), ANSI_RESET.data());
    }
    else
    {
        vfprintf(stdout, format, args);
        va_end(args);
    }
}

[[noreturn]] void Usage()
{
    printf( "Usage: capture -o output.tracy [-a address] [-p port] [-f] [-s seconds] [-m memlimit]\n" );
    exit( 1 );
}

int main( int argc, char** argv )
{
#ifdef _WIN32
    if( !AttachConsole( ATTACH_PARENT_PROCESS ) )
    {
        AllocConsole();
        // leave console mode alone if it fails; that call is best-effort
        SetConsoleMode( GetStdHandle( STD_OUTPUT_HANDLE ), 0x07 );
    }
#endif

    InitIsStdoutATerminal();

    bool overwrite = false;
    const char* address = "127.0.0.1";
    const char* output = nullptr;
    int port = 8086;
    int seconds = -1;
    int64_t memoryLimit = -1;

    int c;
    while( ( c = getopt( argc, argv, "a:o:p:fs:m:" ) ) != -1 )
    {
        switch( c )
        {
        case 'a':
            address = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'p':
            port = atoi( optarg );
            break;
        case 'f':
            overwrite = true;
            break;
        case 's':
            seconds = atoi(optarg);
            break;
        case 'm':
        {
            // clamp needs <algorithm> in older standards: keep semantics
#if __cpp_lib_clamp
            memoryLimit = std::clamp( atoll( optarg ), 1ll, 999ll ) * tracy::GetPhysicalMemorySize() / 100;
#else
            long long pct = atoll(optarg);
            if( pct < 1 ) pct = 1;
            if( pct > 999 ) pct = 999;
            memoryLimit = pct * tracy::GetPhysicalMemorySize() / 100;
#endif
            break;
        }
        default:
            Usage();
            break;
        }
    }

    if( !address || !output ) Usage();

    struct stat st;
    if( stat( output, &st ) == 0 && !overwrite )
    {
        printf( "Output file %s already exists! Use -f to force overwrite.\n", output );
        return 4;
    }

    FILE* test = fopen( output, "wb" );
    if( !test )
    {
        printf( "Cannot open output file %s for writing!\n", output );
        return 5;
    }
    fclose( test );
    unlink( output );

    printf( "Connecting to %s:%i...", address, port );
    fflush( stdout );

    // Create worker. If Tracy's Worker constructor may throw, catching would be necessary.
    tracy::Worker worker( address, port, memoryLimit );

    // Wait for initial data. Keep polling but use a slightly longer sleep to reduce busy-wait.
    constexpr auto pollInterval = std::chrono::milliseconds(100);
    while( !worker.HasData() )
    {
        const auto handshake = worker.GetHandshakeStatus();
        if( handshake == tracy::HandshakeProtocolMismatch )
        {
            printf( "\nThe client you are trying to connect to uses incompatible protocol version.\nMake sure you are using the same Tracy version on both client and server.\n" );
            return 1;
        }
        if( handshake == tracy::HandshakeNotAvailable )
        {
            printf( "\nThe client you are trying to connect to is no longer able to sent profiling data,\nbecause another server was already connected to it.\nYou can do the following:\n\n  1. Restart the client application.\n  2. Rebuild the client application with on-demand mode enabled.\n" );
            return 2;
        }
        if( handshake == tracy::HandshakeDropped )
        {
            printf( "\nThe client you are trying to connect to has disconnected during the initial\nconnection handshake. Please check your network configuration.\n" );
            return 3;
        }
        std::this_thread::sleep_for( pollInterval );
    }

    printf( "\nTimer resolution: %s\n", tracy::TimeToString( worker.GetResolution() ) );

#ifdef _WIN32
    signal( SIGINT, SigInt );
#else
    struct sigaction sigint, oldsigint;
    memset( &sigint, 0, sizeof( sigint ) );
    sigint.sa_handler = SigInt;
    sigaction( SIGINT, &sigint, &oldsigint );
#endif

    const auto firstTime = worker.GetFirstTime();
    auto& lock = worker.GetMbpsDataLock();

    const auto t0 = std::chrono::high_resolution_clock::now();

    // Cache TTY check to avoid repeated atomic loads each iteration (Only for formatting decisions).
    const bool stdoutIsTTY = IsStdoutATerminal();

    while( worker.IsConnected() )
    {
        // Check for signal-driven disconnect first (relaxed is enough).
        if( s_disconnect.load( std::memory_order_relaxed ) )
        {
            worker.Disconnect();
            s_disconnect.store(false, std::memory_order_relaxed);
            break;
        }

        // Safely read data under lock using RAII.
        float lastMbps = 0.f;
        float compRatio = 1.f;
        uint64_t netTotal = 0;
        {
            std::lock_guard<std::mutex> g( lock );
            const auto &mbpsVec = worker.GetMbpsData();
            if( !mbpsVec.empty() ) lastMbps = mbpsVec.back();
            compRatio = worker.GetCompRatio();
            netTotal = worker.GetDataTransferred();
        }

        // Print progress only for TTY to avoid log bloat
        if( stdoutIsTTY )
        {
            const char* unit = "Mbps";
            float unitsPerMbps = 1.f;
            if( lastMbps < 0.1f )
            {
                unit = "Kbps";
                unitsPerMbps = 1000.f;
            }

            // Compose output in a few safe calls. AnsiPrintf will wrap contents as needed.
            AnsiPrintf( ANSI_ERASE_LINE, "\r" ); // erase line prefix
            AnsiPrintf( ANSI_CYAN + std::string_view(ANSI_BOLD), "%7.2f %s", lastMbps * unitsPerMbps, unit );
            printf( " /" );
            AnsiPrintf( ANSI_CYAN + std::string_view(ANSI_BOLD), "%5.1f%%", compRatio * 100.f );
            printf( " =" );
            AnsiPrintf( ANSI_YELLOW + std::string_view(ANSI_BOLD), "%7.2f Mbps", lastMbps / compRatio );
            printf( " | " );
            AnsiPrintf( ANSI_YELLOW, "Tx: ");
            AnsiPrintf( ANSI_GREEN, "%s", tracy::MemSizeToString( netTotal ) );
            printf( " | " );
            AnsiPrintf( ANSI_RED + std::string_view(ANSI_BOLD), "%s", tracy::MemSizeToString( tracy::memUsage.load( std::memory_order_relaxed ) ) );
            if( memoryLimit > 0 )
            {
                printf( " / " );
                AnsiPrintf( ANSI_BLUE + std::string_view(ANSI_BOLD), "%s", tracy::MemSizeToString( memoryLimit ) );
            }
            printf( " | " );
            AnsiPrintf( ANSI_RED, "%s", tracy::TimeToString( worker.GetLastTime() - firstTime ) );
            fflush( stdout );
        }

        std::this_thread::sleep_for( pollInterval );

        if( seconds != -1 )
        {
            const auto dur = std::chrono::high_resolution_clock::now() - t0;
            if( std::chrono::duration_cast<std::chrono::seconds>(dur).count() >= seconds )
            {
                s_disconnect.store(true, std::memory_order_relaxed);
            }
        }
    }

    const auto t1 = std::chrono::high_resolution_clock::now();

    const auto& failure = worker.GetFailureType();
    if( failure != tracy::Worker::Failure::None )
    {
        AnsiPrintf( ANSI_RED + std::string_view(ANSI_BOLD), "\nInstrumentation failure: %s", tracy::Worker::GetFailureString( failure ) );
        auto& fd = worker.GetFailureData();
        if( !fd.message.empty() )
        {
            printf( "\nContext: %s", fd.message.c_str() );
        }
        if( fd.callstack != 0 )
        {
            AnsiPrintf( ANSI_BOLD, "\nFailure callstack:\n" );
            auto& cs = worker.GetCallstack( fd.callstack );
            int fidx = 0;
            for( auto& entry : cs )
            {
                auto frameData = worker.GetCallstackFrame( entry );
                if( !frameData )
                {
                    printf( "%3i. %p\n", fidx++, (void*)worker.GetCanonicalPointer( entry ) );
                }
                else
                {
                    const auto fsz = frameData->size;
                    for( uint8_t f=0; f<fsz; f++ )
                    {
                        const auto& frame = frameData->data[f];
                        const char* txt = worker.GetString( frame.name );

                        if( fidx == 0 && f != fsz-1 )
                        {
                            auto test = tracy::s_tracyStackFrames;
                            bool match = false;
                            do
                            {
                                if( strcmp( txt, *test ) == 0 )
                                {
                                    match = true;
                                    break;
                                }
                            }
                            while( *++test );
                            if( match ) continue;
                        }

                        if( f == fsz-1 )
                        {
                            printf( "%3i. ", fidx++ );
                        }
                        else
                        {
                            AnsiPrintf( ANSI_BLACK + std::string_view(ANSI_BOLD), "inl. " );
                        }
                        AnsiPrintf( ANSI_CYAN, "%s  ", txt );
                        txt = worker.GetString( frame.file );
                        if( frame.line == 0 )
                        {
                            AnsiPrintf( ANSI_YELLOW, "(%s)", txt );
                        }
                        else
                        {
                            AnsiPrintf( ANSI_YELLOW, "(%s:%" PRIu32 ")", txt, frame.line );
                        }
                        if( frameData->imageName.Active() )
                        {
                            AnsiPrintf( ANSI_MAGENTA, " %s\n", worker.GetString( frameData->imageName ) );
                        }
                        else
                        {
                            printf( "\n" );
                        }
                    }
                }
            }
        }
    }

    printf( "\nFrames: %" PRIu64 "\nTime span: %s\nZones: %s\nElapsed time: %s\nSaving trace...",
        worker.GetFrameCount( *worker.GetFramesBase() ), tracy::TimeToString( worker.GetLastTime() - firstTime ), tracy::RealToString( worker.GetZoneCount() ),
        tracy::TimeToString( std::chrono::duration_cast<std::chrono::nanoseconds>( t1 - t0 ).count() ) );
    fflush( stdout );

    auto f = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output, tracy::FileCompression::Zstd, 3, 4 ) );
    if( f )
    {
        worker.Write( *f, false );
        AnsiPrintf( ANSI_GREEN + std::string_view(ANSI_BOLD), " done!\n" );
        f->Finish();
        const auto stats = f->GetCompressionStatistics();
        printf( "Trace size %s (%.2f%% ratio)\n", tracy::MemSizeToString( stats.second ), 100.f * stats.second / stats.first );
    }
    else
    {
        AnsiPrintf( ANSI_RED + std::string_view(ANSI_BOLD), " failed!\n");
    }

    return 0;
}
