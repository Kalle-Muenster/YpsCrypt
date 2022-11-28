// Test.cs
/////////////////////////////////

using Consola;
using Consola.Test;
using System.Collections.Generic;
using Yps;

List<string> Args = new( args );

if( Args.Contains("-h")
 || Args.Contains("/?")
 || Args.Contains("--help") )
{
    StdStream.Init( CreationFlags.TryConsole );
    ILocked stream = StdStream.Out.Stream;
    stream.Put("\nTest result options:\n    ")
        .Put("--verbose, -v    -    generate ")
        .Put("more detailed result log which ")
        .Put("also contains all PASS results\n    ")
        .Put("--xmllogs, -x    -    generate ")
        .Put("xml test results\n    ")
        .Put("--timelog, -t    -    timestamp")
        .Put(" all log entries\n")
    .End();
    return 0;
}

/////////////////////////////////

StdStream.Init(
    CreationFlags.TryConsole |
    CreationFlags.NoInputLog |
    CreationFlags.CreateLog
);

Test test = new CrypsTests(
    Args.Contains("-v") || Args.Contains("--verbose"),
    Args.Contains("-x") || Args.Contains("--xmllogs"),
    Args.Contains("-t") || Args.Contains("--timelog")
).Run();

return test.hasCrashed() ? -1
     : test.hasPassed() ?  0
     : test.getFailures();
