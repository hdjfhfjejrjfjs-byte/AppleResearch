// harness/main.m — runs every compiled fuzzer once per launch, each on its own
// detached pthread.  The iOS sandbox rejects fork() from third-party apps
// (EPERM), so process isolation is unavailable: a fuzzer that hangs cannot be
// killed, it keeps fuzzing in the background after its timeout while the
// runner advances to the next entry.
//
// Crash recovery is "advance first": the resume record is moved to the next
// fuzzer BEFORE that fuzzer starts.  If it takes down user space (system crash
// log) or the kernel (panic log), the next launch resumes after it and never
// repeats it; the last START line in harness.log identifies the culprit.
//
// Results: Documents/harness.log + live on-screen console.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "poc_table.h"

#ifndef POC_TIMEOUT_SECONDS
#define POC_TIMEOUT_SECONDS 60
#endif

static NSString *gStatePath;
static NSString *gLogPath;
static NSFileHandle *gLog;
static int gLogFD = -1;          // stdout/stderr target, captured in main()
static UITextView *gConsole;
static _Atomic int gRunActive;   // 0 = idle; claimed before run_all is dispatched

static void console_line(NSString *line) {
    NSLog(@"[FuzzHarness] %@", line);
    [gLog writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    dispatch_async(dispatch_get_main_queue(), ^{
        gConsole.text = [gConsole.text stringByAppendingFormat:@"%@\n", line];
        [gConsole scrollRangeToVisible:NSMakeRange(gConsole.text.length, 0)];
    });
}

static void log_line(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    console_line(line);
}

static void load_state(int *idx, int *att) {
    *idx = 0; *att = 0;
    NSString *s = [NSString stringWithContentsOfFile:gStatePath encoding:NSUTF8StringEncoding error:nil];
    if (s) sscanf(s.UTF8String, "%d %d", idx, att);
    if (*idx < 0) *idx = 0;             // never index outside kPocs[]
    if (*idx > POC_COUNT) *idx = POC_COUNT;
    if (*att < 0) *att = 0;
}

static void save_state(int idx, int att) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%d %d\n", idx, att);
    if (n <= 0 || n >= (int)sizeof(buf)) return;
    // Direct write + flush: writeToFile:atomically: leaves the rename and the
    // data in the cache, so a panic could resurrect an older resume point.
    int fd = open([gStatePath fileSystemRepresentation], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    ssize_t w = write(fd, buf, (size_t)n);
    if (w == n) {
        if (fcntl(fd, F_FULLFSYNC) < 0) fsync(fd);
    }
    close(fd);
}

static int run_begin(void) {
    int expected = 0;
    return atomic_compare_exchange_strong(&gRunActive, &expected, 1);
}

// One entry per launched fuzzer.  The slot is heap-allocated and never reused:
// a thread that outlives its timeout still owns its slot until it returns, and
// a later Rerun must not alias it.
struct RunSlot {
    const char *name;
    int (*func)(int, char **);
    volatile int done;
    int ret;
};

static void *run_slot(void *arg) {
    struct RunSlot *slot = (struct RunSlot *)arg;
    // The fuzzers are renamed mains; give them a valid argv[0] because some
    // (fuzzers/caf/harness.c) dereference it before checking argc.
    char *poc_argv[] = { (char *)slot->name, NULL };
    slot->ret = slot->func(1, poc_argv);
    __sync_synchronize();               // publish ret before done
    slot->done = 1;
    return NULL;
}

static void run_all(void) {
    int idx = 0, att = 0;
    load_state(&idx, &att);
    (void)att;  // legacy attempts field: still parsed, no longer used

    if (idx >= POC_COUNT) {
        log_line(@"=== ALL DONE — %d fuzzers launched on previous runs ===", POC_COUNT);
        log_line(@"tap Rerun to start over");
        return;
    }

    log_line(@"=== FuzzHarness: %d fuzzers, resume at %d, timeout %ds each ===",
             POC_COUNT, idx + 1, POC_TIMEOUT_SECONDS);

    int exited = 0, timed_out = 0, failed = 0;

    for (int i = idx; i < POC_COUNT; i++) {
        struct RunSlot *slot = calloc(1, sizeof(*slot));
        if (slot == NULL) {
            log_line(@"[%d/%d] %s — THREAD FAILED (out of memory)", i + 1, POC_COUNT, kPocs[i].name);
            save_state(i + 1, 0);
            failed++;
            continue;
        }
        slot->name = kPocs[i].name;
        slot->func = kPocs[i].func;

        log_line(@"[%d/%d] %s — START", i + 1, POC_COUNT, kPocs[i].name);
        // Advance before launch: if this fuzzer crashes the app or panics the
        // kernel, the next launch resumes at i + 1 and never repeats it.
        save_state(i + 1, 0);

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int rc = pthread_create(&tid, &attr, run_slot, slot);
        pthread_attr_destroy(&attr);
        if (rc != 0) {
            log_line(@"[%d/%d] %s — THREAD FAILED (%d)", i + 1, POC_COUNT, kPocs[i].name, rc);
            free(slot);
            failed++;
            continue;
        }

        // Never join and never kill: a timed-out fuzzer keeps running in the
        // background (that is the point) and keeps its slot.
        int slot_timed_out = 0;
        time_t start = time(NULL);
        while (!slot->done) {
            if (time(NULL) - start >= POC_TIMEOUT_SECONDS) {
                slot_timed_out = 1;
                break;
            }
            usleep(100 * 1000);
        }

        if (slot_timed_out) {
            log_line(@"[%d/%d] %s — TIMEOUT (%ds) — 后台线程继续运行",
                     i + 1, POC_COUNT, kPocs[i].name, POC_TIMEOUT_SECONDS);
            timed_out++;
        } else {
            __sync_synchronize();       // pair with the writer before reading ret
            log_line(@"[%d/%d] %s — exit %d", i + 1, POC_COUNT, kPocs[i].name, slot->ret);
            free(slot);
            exited++;
        }
    }

    if (failed == 0) {
        log_line(@"=== ALL %d LAUNCHED — %d exited, %d timed out (running in background) ===",
                 POC_COUNT, exited, timed_out);
    } else {
        log_line(@"=== ALL %d LAUNCHED — %d exited, %d timed out (running in background), %d failed to start ===",
                 POC_COUNT, exited, timed_out, failed);
    }
}

static void run_all_once(void) {
    run_all();
    atomic_store(&gRunActive, 0);
}

@interface HarnessAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@interface HarnessVC : UIViewController
@end

@implementation HarnessVC {
    BOOL _started;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    gConsole = [[UITextView alloc] initWithFrame:self.view.bounds];
    gConsole.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    gConsole.backgroundColor = [UIColor blackColor];
    gConsole.textColor = [UIColor greenColor];
    gConsole.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    gConsole.editable = NO;
    gConsole.text = @"";
    [self.view addSubview:gConsole];

    UIButton *rerun = [UIButton buttonWithType:UIButtonTypeSystem];
    [rerun setTitle:@"Rerun" forState:UIControlStateNormal];
    rerun.frame = CGRectMake(self.view.bounds.size.width - 90, 40, 80, 36);
    rerun.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    [rerun addTarget:self action:@selector(rerunTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:rerun];
}

- (void)rerunTapped {
    if (!run_begin()) return;   // an active run owns the state file and console
    save_state(0, 0);
    gConsole.text = @"";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        run_all_once();
    });
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    if (_started) return;
    _started = YES;
    if (!run_begin()) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        run_all_once();
    });
}

@end

@implementation HarnessAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Keep the device awake: auto-lock suspends the app and stops all fuzzing.
    [UIApplication sharedApplication].idleTimerDisabled = YES;
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[HarnessVC alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docs = [paths objectAtIndex:0];
        gStatePath = [docs stringByAppendingPathComponent:@"harness_state.txt"];
        gLogPath   = [docs stringByAppendingPathComponent:@"harness.log"];
        // Append across launches: the log of the run that panicked is evidence.
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:gLogPath]) {
            [fm createFileAtPath:gLogPath contents:nil attributes:nil];
        }
        gLog = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
        [gLog seekToEndOfFile];
        gLogFD = gLog ? [gLog fileDescriptor] : -1;

        // One process-wide redirect before any fuzzer thread starts: fuzzer
        // printf/fprintf and NSLog output land in Documents/harness.log (the
        // threads inherit fds 1 and 2).  Unbuffered so a crash does not lose
        // the last lines.
        if (gLogFD >= 0) {
            dup2(gLogFD, STDOUT_FILENO);
            dup2(gLogFD, STDERR_FILENO);
        }
        setvbuf(stdout, NULL, _IONBF, 0);

        return UIApplicationMain(argc, argv, nil, NSStringFromClass([HarnessAppDelegate class]));
    }
}
