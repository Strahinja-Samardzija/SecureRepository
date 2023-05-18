using SecureRepository;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.File("../../../logs/log.txt", flushToDiskInterval: TimeSpan.FromSeconds(1), rollingInterval: RollingInterval.Day)
    .CreateLogger();

WelcomeScreen.Show();
Log.CloseAndFlush();