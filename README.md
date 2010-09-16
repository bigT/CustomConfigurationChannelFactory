CustomConfigurationChannelFactory
=================================

An implementation of a WCF 4.0 [ConfigurationChannelFactory](http://msdn.microsoft.com/en-us/library/dd575311.aspx) 
equivalent for WCF 3.0 - 3.5. Allows creation of WCF clients that can take in any Configuration removing a dependency 
on the App.config or Web.config of the hosting application.

Example:
--------

	Configuration configuration = ConfigurationManager.OpenMappedExeConfiguration(
		new ExeConfigurationFileMap { ExeConfigFilename = @"C:\Temp\CustomClient.config" }, ConfigurationUserLevel.None);

	CustomConfigurationChannelFactory<ITestService> factory =
		new CustomConfigurationChannelFactory<ITestService>("ITestService", configuration, null);

	ITestService client = factory.CreateChannel();
	string returnValue = client.TesMethod("test");
	factory.Close();
