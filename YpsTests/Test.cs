// Test.cs
/////////////////////////////////

using Consola;
using System.Collections.Generic;
using Int24Tests.Tests;
using Yps;

List<string> Args = new( args );

/////////////////////////////////

StdStream.Init(
    CreationFlags.TryConsole |
    CreationFlags.NoInputLog |
    CreationFlags.CreateLog
);

TestCase test = new CrypsTests(
    Args.Contains("-v") ||
    Args.Contains("--verbose")
).Run();

return test.wasErrors() ?
  -1 : test.hasPassed() ?
   0 : test.getFailures();
