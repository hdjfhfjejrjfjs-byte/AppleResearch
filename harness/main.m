// harness/main.m — runs every compiled fuzzer sequentially, once per launch.
// Each fuzzer runs in a forked child with a hard timeout, so a user-space crash
// or an infinite loop cannot stop the run. State persists across kernel panics:
// the next launch resumes at the fuzzer that was running when the device died.
// Results: Documents/harness.log + live on-screen console.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include "poc_table.h"

#ifndef POC_TIMEOUT_SECONDS
#define POC_TIMEOUT_SECONDS 60
#endif
#define MAX_ATTEMPTS 2   // skip a fuzzer after this many launches die on it

static NSString *gStatePath;
static NSString *gLogPath;
static NSFileHandle *gLog;
static UITextView *gConsole;

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
}

static void save_state(int idx, int att) {
    [[NSString stringWithFormat:@"%d %d\n", idx, att] writeToFile:gStatePath
        atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static void run_all(void) {
    int idx = 0, att = 0;
    load_state(&idx, &att);

    if (idx >= POC_COUNT) {
        log_line(@"=== ALL DONE — %d fuzzers completed on previous runs ===", POC_COUNT);
        log_line(@"tap Rerun to start over");
        return;
    }

    log_line(@"=== FuzzHarness: %d fuzzers, resume at %d, timeout %ds each ===",
             POC_COUNT, idx + 1, POC_TIMEOUT_SECONDS);

    for (int i = idx; i < POC_COUNT; i++) {
        if (i == idx && att >= MAX_ATTEMPTS) {
            log_line(@"[%d/%d] %s — SKIPPED (%d attempts died on it)",
                     i + 1, POC_COUNT, kPocs[i].name, att);
            save_state(i + 1, 0);
            continue;
        }
        if (i != idx) att = 0;

        save_state(i, att + 1);
        log_line(@"[%d/%d] %s — START", i + 1, POC_COUNT, kPocs[i].name);

        pid_t pid = fork();
        if (pid == 0) {
            setvbuf(stdout, NULL, _IONBF, 0);
            int r = kPocs[i].func(0, NULL);
            fflush(NULL);
            _exit(r);
        }
        if (pid < 0) {
            log_line(@"[%d/%d] %s — FORK FAILED", i + 1, POC_COUNT, kPocs[i].name);
            save_state(i + 1, 0);
            continue;
        }

        int status = 0;
        int timed_out = 0;
        time_t start = time(NULL);
        for (;;) {
            if (waitpid(pid, &status, WNOHANG) == pid) break;
            if (time(NULL) - start >= POC_TIMEOUT_SECONDS) {
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                timed_out = 1;
                break;
            }
            usleep(100 * 1000);
        }

        if (timed_out) {
            log_line(@"[%d/%d] %s — TIMEOUT (%ds, killed)",
                     i + 1, POC_COUNT, kPocs[i].name, POC_TIMEOUT_SECONDS);
        } else if (WIFSIGNALED(status)) {
            log_line(@"[%d/%d] %s — CRASH signal %d (finding — check crash log)",
                     i + 1, POC_COUNT, kPocs[i].name, WTERMSIG(status));
        } else {
            log_line(@"[%d/%d] %s — exit %d",
                     i + 1, POC_COUNT, kPocs[i].name, WEXITSTATUS(status));
        }

        save_state(i + 1, 0);
    }

    log_line(@"=== ALL %d FUZZERS DONE ===", POC_COUNT);
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
    save_state(0, 0);
    gConsole.text = @"";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        run_all();
    });
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    if (_started) return;
    _started = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        run_all();
    });
}

@end

@implementation HarnessAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
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
        [[NSFileManager defaultManager] createFileAtPath:gLogPath contents:nil attributes:nil];
        gLog = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
        [gLog seekToEndOfFile];

        return UIApplicationMain(argc, argv, nil, NSStringFromClass([HarnessAppDelegate class]));
    }
}
