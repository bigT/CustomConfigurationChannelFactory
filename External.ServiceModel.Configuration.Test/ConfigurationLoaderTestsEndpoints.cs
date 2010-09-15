// <copyright file="ConfigurationLoaderTestsEndpoints.cs" company="Taras V. Alenin"> 
//
//  Copyright (c) 2010 Taras V. Alenin
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//
// </copyright>
namespace External.ServiceModel.Configuration.Test
{
    using System;
    using System.Configuration;
    using System.ServiceModel;
    using System.ServiceModel.Configuration;
    using System.ServiceModel.Description;

    using External.ServiceModel.Configuration;
    using External.ServiceModel.Configuration.Test.Contract;
    using Xunit;

    /// <summary>
    /// Test initialisation of the WCF end point from custom configuration.
    /// </summary>
    public class ConfigurationLoaderTestsEndpoints
    {
        #region Fields
        /// <summary>
        /// Contract name used by the test contract endpoint.
        /// </summary>
        private const string ContractName = "TestService";

        /// <summary>
        /// Contract namespace used by the test contract endpoint.
        /// </summary>
        private const string ContractNamespace = "Test.Service";
        #endregion

        /// <summary>
        /// Tests an initialisation from an empty configuration context.
        /// </summary>
        [Fact]
        public void TestEmptyConfigurationExcpetions()
        {
            ServiceModelSectionGroup context = this.CreateServiceModelSectionGroup();
            Assert.Throws(typeof(InvalidOperationException), delegate { this.LoadServiceEndPoint("Test", context); });
            Assert.Throws(typeof(InvalidOperationException), delegate { this.LoadServiceEndPoint("*", context); });
        }

        /// <summary>
        /// Test matching endpoint by wildcard.
        /// </summary>
        [Fact]
        public void TestWildcardMatch()
        {
            EndpointAddress address = new EndpointAddress("http://localhost/Test");
            ChannelEndpointElement endpoint = new ChannelEndpointElement(address, typeof(ITestService).FullName);

            // Construct configuration settings
            ServiceModelSectionGroup context = this.CreateServiceModelSectionGroup();
            context.Client.Endpoints.Add(endpoint);

            // Load endpoint from settings.
            ServiceEndpoint loadedEndpoint = this.LoadServiceEndPoint("*", context);

            // Assert the endpoint loaded correctly.
            Assert.Equal(address, loadedEndpoint.Address);
            Assert.Equal(endpoint.Contract, loadedEndpoint.Contract.ContractType.FullName);
        }

        /// <summary>
        /// Test matching endpoint by wildcard with no matching contract type.
        /// </summary>
        [Fact]
        public void TestNoMatchingContractWhildcard()
        {
            // Construct configuration settings
            ChannelEndpointElement endpoint = new ChannelEndpointElement(null, typeof(ITestService).FullName + "0000");
            ServiceModelSectionGroup context = this.CreateServiceModelSectionGroup();
            context.Client.Endpoints.Add(endpoint);

            Assert.Throws(typeof(InvalidOperationException), delegate { this.LoadServiceEndPoint("*", context); });
        }

        /// <summary>
        /// Test matching endpoint by wildcard more then one endpoint defined no duplicate contracts.
        /// </summary>
        [Fact]
        public void TestMatchingContractWildcardManyEndpointsOneMatch()
        {
            // Construct configuration settings
            ChannelEndpointElement endpoint1 = new ChannelEndpointElement(null, typeof(ITestService).FullName) { Name = "Test1" };
            ChannelEndpointElement endpoint2 = new ChannelEndpointElement(null, typeof(ITestService).FullName + "0000") { Name = "Test2" };
            ServiceModelSectionGroup context = this.CreateServiceModelSectionGroup();
            context.Client.Endpoints.Add(endpoint1);
            context.Client.Endpoints.Add(endpoint2);

            ServiceEndpoint actualEndpoint = this.LoadServiceEndPoint("*", context);
            Assert.Equal(endpoint1.Contract, actualEndpoint.Contract.ContractType.FullName);
        }

        /// <summary>
        /// Test matching endpoint by wildcard more then one endpoint with duplicate contracts.
        /// </summary>
        [Fact]
        public void TestMatchingContractWildcardManyEndpointsTwoMatch()
        {
            // Construct configuration settings
            ChannelEndpointElement endpoint1 = new ChannelEndpointElement(null, typeof(ITestService).FullName) { Name = "Test1" };
            ChannelEndpointElement endpoint2 = new ChannelEndpointElement(null, typeof(ITestService).FullName) { Name = "Test2" };
            ServiceModelSectionGroup context = this.CreateServiceModelSectionGroup();
            context.Client.Endpoints.Add(endpoint1);
            context.Client.Endpoints.Add(endpoint2);

            Assert.Throws(typeof(InvalidOperationException), delegate { this.LoadServiceEndPoint("*", context); });
        }

        /// <summary>
        /// Test matching endpoint by a specific name.
        /// </summary>
        [Fact]
        public void TestMatchingContractBySpecificName()
        {
            // Construct configuration settings
            ChannelEndpointElement endpoint1 = new ChannelEndpointElement(null, typeof(ITestService).FullName) { Name = "Test1" };
            ChannelEndpointElement endpoint2 = new ChannelEndpointElement(null, typeof(ITestService).FullName + "0000") { Name = "Test2" };
            ServiceModelSectionGroup context = this.CreateServiceModelSectionGroup();
            context.Client.Endpoints.Add(endpoint1);
            context.Client.Endpoints.Add(endpoint2);

            Assert.DoesNotThrow(delegate { this.LoadServiceEndPoint("Test1", context); });
            Assert.Throws(typeof(InvalidOperationException), delegate { this.LoadServiceEndPoint("TestXYZ", context); });
            Assert.Throws(typeof(InvalidOperationException), delegate { this.LoadServiceEndPoint("Test2", context); });
        }

        #region Private
        /// <summary>
        /// Initialises an instance of a service endpoint from the provided configuration context. 
        /// </summary>
        /// <param name="configurationName">The name property in an endpoint configuration element.</param>
        /// <param name="context">Configuration context used to read settings from.</param>
        /// <returns>An instance of a service endpoint initialised with the provided configuration settings.</returns>
        private ServiceEndpoint LoadServiceEndPoint(string configurationName, ServiceModelSectionGroup context)
        {
            CustomConfigurationChannelFactory<object>.ConfigurationLoader loader = new CustomConfigurationChannelFactory<object>.ConfigurationLoader(context);
            return loader.LoadChannelBehaviors(this.CreateServiceEndpoint(), configurationName);
        }

        /// <summary>
        /// Creates an empty service endpoint.
        /// </summary>
        /// <returns>An instance of a service endpoint.</returns>
        private ServiceEndpoint CreateServiceEndpoint()
        {
            return new ServiceEndpoint(ContractDescription.GetContract(typeof(ITestService)));
        }

        /// <summary>
        /// Creates an empty system.serviceModel configuration group.
        /// </summary>
        /// <returns>Returns an instance of an empty system.serviceModel configuration group.</returns>
        private ServiceModelSectionGroup CreateServiceModelSectionGroup()
        {
            Configuration config = ConfigurationManager.OpenMappedExeConfiguration(new ExeConfigurationFileMap() { ExeConfigFilename = "Test.config" }, ConfigurationUserLevel.None);
            return (ServiceModelSectionGroup)config.SectionGroups.Get("system.serviceModel");
        }
        #endregion
    }
}