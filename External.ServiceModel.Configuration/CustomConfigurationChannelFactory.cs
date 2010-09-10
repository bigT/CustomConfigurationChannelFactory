// <copyright file="CustomConfigurationChannelFactory.cs" company="Taras V. Alenin"> 
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
namespace External.ServiceModel.Configuration.Service
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Globalization;
    using System.Reflection;
    using System.Runtime.CompilerServices;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Permissions;
    using System.ServiceModel;
    using System.ServiceModel.Channels;
    using System.ServiceModel.Configuration;
    using System.ServiceModel.Description;
    using System.Text;
    using System.Web.Configuration;

    /// <summary>
    /// Provides the generic functionality to create a channel based on specific configuration for a specific type.
    /// </summary>
    /// <typeparam name="TChannel">The type of communications channel to specify for the endpoint element that is created.</typeparam>
    public class CustomConfigurationChannelFactory<TChannel> : ChannelFactory<TChannel>
    {
        /// <summary>
        /// Initializes a new instance of the CustomConfigurationChannelFactory class with the 
        /// specified endpoint configuration name, <see cref="System.Configuration.Configuration">Configuration</see>  object, 
        /// and the <see cref="System.ServiceModel.EndpointAddress">EndpointAddress</see> object.
        /// </summary>
        /// <param name="endpointConfigurationName">The name property in an endpoint configuration element.</param>
        /// <param name="configuration">The settings that define the information in the endpoint element.</param>
        /// <param name="remoteAddress">The IP address of a destination endpoint in a client or server session.</param>
        public CustomConfigurationChannelFactory(string endpointConfigurationName, System.Configuration.Configuration configuration, EndpointAddress remoteAddress)
            : base(typeof(TChannel))
        {
            this.ServiceModelGroup = ServiceModelSectionGroup.GetSectionGroup(configuration);
            this.InitializeEndpoint(endpointConfigurationName, remoteAddress);
        }

        /// <summary>
        /// Gets or sets configuration system.serviceModel group.
        /// </summary>
        private ServiceModelSectionGroup ServiceModelGroup { get; set; }

        /// <summary>
        /// Initializes the channel factory with the behaviours provided by a specified configuration file and 
        /// with those in the service endpoint of the channel factory.
        /// </summary>
        /// <param name="endpointConfigurationName">The name property in an endpoint configuration element.</param>
        protected override void ApplyConfiguration(string endpointConfigurationName)
        {
            ConfigurationLoader loader = new ConfigurationLoader(this.ServiceModelGroup);
            loader.LoadChannelBehaviors(this.Endpoint, endpointConfigurationName);
        }

        #region Private Classes

        /// <summary>
        /// Partial trust evaluation helpers.
        /// </summary>
        private static class PartialTrustHelpers
        {
            /// <summary>
            /// AllowPartiallyTrustedCallersAttribute (APTCA) 
            /// </summary>
            [SecurityCritical]
            private static Type aptca;

            /// <summary>
            /// Determines whether specified type allows partial trust callers.
            /// </summary>
            /// <param name="type">A type to be tested.</param>
            /// <returns>True if partially trusted caller are allowed, false otherwise.</returns>
            [SecurityCritical]
            internal static bool IsTypeAptca(Type type)
            {
                Assembly assembly = type.Assembly;
                if (!IsAssemblyAptca(assembly))
                {
                    return !IsAssemblySigned(assembly);
                }

                return true;
            }

            /// <summary>
            /// Determines whether an assembly is signed.
            /// </summary>
            /// <param name="assembly">An assembly to be tested</param>
            /// <returns>True is assembly is signed, false otherwise.</returns>
            [SecurityCritical, FileIOPermission(SecurityAction.Assert, Unrestricted = true)]
            private static bool IsAssemblySigned(Assembly assembly)
            {
                byte[] publicKeyToken = assembly.GetName().GetPublicKeyToken();
                return (publicKeyToken != null) && (publicKeyToken.Length > 0);
            }

            /// <summary>
            /// Determines whether an assembly is marked as AllowPartiallyTrustedCallersAttribute (APTCA).
            /// </summary>
            /// <param name="assembly">An assembly to be tested.</param>
            /// <returns>True is assembly is marked as AllowPartiallyTrustedCallersAttribute (APTCA), false otherwise.</returns>
            [SecurityCritical]
            private static bool IsAssemblyAptca(Assembly assembly)
            {
                if (aptca == null)
                {
                    aptca = typeof(AllowPartiallyTrustedCallersAttribute);
                }

                return assembly.GetCustomAttributes(aptca, false).Length > 0;
            }
        }

        /// <summary>
        /// Configuration loader helpers.
        /// </summary>
        private class ConfigurationLoader
        {
            /// <summary>
            /// Used to check for secular configuration references.
            /// </summary>
            [ThreadStatic]
            private static List<string> resolvedBindings;

            /// <summary>
            /// A cached copy if the configuration permissions. Used by the ode
            /// that determines partial trust.
            /// </summary>
            [SecurityCritical]
            private static ConfigurationPermission configurationPermission;

            /// <summary>
            /// Initializes a new instance of the ConfigurationLoader class.
            /// </summary>
            /// <param name="context">Configuration properties to be loaded.</param>
            public ConfigurationLoader(ServiceModelSectionGroup context)
            {
                this.ConfiguraionContext = context;
            }

            /// <summary>
            /// Gets a system configuration permissions.
            /// </summary>
            private static ConfigurationPermission ConfigurationPermission
            {
                [SecurityTreatAsSafe, SecurityCritical]
                get
                {
                    if (configurationPermission == null)
                    {
                        configurationPermission = new ConfigurationPermission(PermissionState.Unrestricted);
                    }

                    return configurationPermission;
                }
            }

            /// <summary>
            /// Gets or sets 'system.serviceModel' section that will be used as the source
            /// of the configuration.
            /// </summary>
            private ServiceModelSectionGroup ConfiguraionContext { get; set; }

            /// <summary>
            /// Loads configured channel behaviours into the ServiceEndpoint object.
            /// </summary>
            /// <param name="serviceEndpoint">Service end point to be configured.</param>
            /// <param name="configurationName">The name property in an endpoint configuration element.</param>
            /// <returns>The same endpoint as passed as a parameter.</returns>
            public ServiceEndpoint LoadChannelBehaviors(ServiceEndpoint serviceEndpoint, string configurationName)
            {
                bool isWildcard = string.Equals(configurationName, "*", StringComparison.Ordinal);
                ChannelEndpointElement provider = this.LookupChannel(configurationName, serviceEndpoint.Contract.ConfigurationName, isWildcard);

                if (provider == null)
                {
                    if (isWildcard)
                    {
                        throw new InvalidOperationException(string.Format(
                             "Could not find default endpoint element that references contract '{0}' in the ServiceModel " +
                             "client configuration section. This might be because no configuration file was found for your " +
                             "application, or because no endpoint element matching this contract could be found in the client element.",
                             serviceEndpoint.Contract.ConfigurationName));
                    }

                    throw new InvalidOperationException(string.Format(
                            "Could not find endpoint element with name '{0}' and contract '{1}' in the ServiceModel " +
                            "client configuration section. This might be because no configuration file was found for " +
                            "your application, or because no endpoint element matching this name could be found in the client element.",
                            configurationName,
                            serviceEndpoint.Contract.ConfigurationName));
                }

                if ((serviceEndpoint.Binding == null) && !string.IsNullOrEmpty(provider.Binding))
                {
                    serviceEndpoint.Binding = this.LookupBinding(provider.Binding, provider.BindingConfiguration);
                }

                if (((serviceEndpoint.Address == null) && (provider.Address != null)) && (provider.Address.OriginalString.Length > 0))
                {
                    serviceEndpoint.Address = new EndpointAddress(provider.Address, this.LoadIdentity(provider.Identity), provider.Headers.Headers);
                }

                ContextInformation context = (ContextInformation)provider.GetType().InvokeMember(
                     "System.ServiceModel.Configuration.IConfigurationContextProviderInternal.GetEvaluationContext",
                     BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance,
                     null,
                     provider,
                     null,
                     CultureInfo.InvariantCulture);

                CommonBehaviorsSection commonBehaviors = this.LookupCommonBehaviors(context);
                if ((commonBehaviors != null) && (commonBehaviors.EndpointBehaviors != null))
                {
                    LoadBehaviors<IEndpointBehavior>(commonBehaviors.EndpointBehaviors, serviceEndpoint.Behaviors, true);
                }

                EndpointBehaviorElement endpointBehaviors = this.LookupEndpointBehaviors(provider.BehaviorConfiguration, context);
                if (endpointBehaviors != null)
                {
                    LoadBehaviors<IEndpointBehavior>(endpointBehaviors, serviceEndpoint.Behaviors, false);
                }

                return serviceEndpoint;
            }

            #region Private
            /// <summary>
            /// Determines whether to skip initialization of common behaviours.
            /// </summary>
            /// <param name="behaviorType">Type to be tested.</param>
            /// <param name="isPartialTrust">Reference to a partial trust flag.</param>
            /// <returns>True is common behaviours should be skipped. False otherwise.</returns>
            [SecurityCritical]
            private static bool ShouldSkipCommonBehavior(Type behaviorType, ref bool? isPartialTrust)
            {
                bool flag = false;
                if (!isPartialTrust.HasValue)
                {
                    if (!PartialTrustHelpers.IsTypeAptca(behaviorType))
                    {
                        isPartialTrust = new bool?(!ThreadHasConfigurationPermission());
                        flag = isPartialTrust.Value;
                    }

                    return flag;
                }

                if (isPartialTrust.Value)
                {
                    flag = !PartialTrustHelpers.IsTypeAptca(behaviorType);
                }

                return flag;
            }

            /// <summary>
            /// Determines whether the current thread has Configuration permissions.
            /// </summary>
            /// <returns>True if the current thread does have the permissions. False otherwise.</returns>
            [SecurityCritical]
            private static bool ThreadHasConfigurationPermission()
            {
                try
                {
                    ConfigurationPermission.Demand();
                }
                catch (SecurityException)
                {
                    return false;
                }

                return true;
            }

            /// <summary>
            /// Checks whether the configuration is above web application.
            /// </summary>
            /// <param name="contextInformation">Configuration context.</param>
            /// <returns>True if context is above application, false otherwise.</returns>
            [MethodImpl(MethodImplOptions.NoInlining)]
            private static bool IsWebConfigAboveApplication(ContextInformation contextInformation)
            {
                WebContext hostingContext = contextInformation.HostingContext as WebContext;
                return (hostingContext != null) && (hostingContext.ApplicationLevel == WebApplicationLevel.AboveApplication);
            }

            /// <summary>
            /// Checks whether the configuration is above application.
            /// </summary>
            /// <param name="contextInformation">Configuration context.</param>
            /// <returns>True if context is above application, false otherwise.</returns>
            private static bool IsConfigAboveApplication(ContextInformation contextInformation)
            {
                if (contextInformation == null)
                {
                    return true;
                }

                if (contextInformation.IsMachineLevel)
                {
                    return true;
                }

                if (contextInformation.HostingContext is ExeContext)
                {
                    return false;
                }

                return IsWebConfigAboveApplication(contextInformation);
            }

            /// <summary>
            /// Retrieves channel endpoint configuration.
            /// </summary>
            /// <param name="configurationName">The name property in an endpoint configuration element.</param>
            /// <param name="contractName">Full type name of the service contract including namespace. The contract property in an endpoint configuration element.</param>
            /// <param name="isWildcard">A flag that determines whether a wildcard was passed as the configuratioName.</param>
            /// <returns>Returns a channel endpoint configuration.</returns>
            private ChannelEndpointElement LookupChannel(string configurationName, string contractName, bool isWildcard)
            {
                ClientSection section = this.ConfiguraionContext.Client;
                ChannelEndpointElement cnannelEndPoint = null;

                foreach (ChannelEndpointElement element in section.Endpoints)
                {
                    if (element.Contract != contractName || (element.Name != configurationName && !isWildcard))
                    {
                        continue;
                    }

                    if (cnannelEndPoint != null)
                    {
                        if (isWildcard)
                        {
                            new InvalidOperationException(string.Format("An endpoint configuration section for contract '{0}' could not be loaded because more than one endpoint configuration for that contract was found. Please indicate the preferred endpoint configuration section by name.", contractName));
                        }

                        new InvalidOperationException(string.Format("The endpoint configuration section for contract '{0}' with name '{1}' could not be loaded because more than one endpoint configuration with the same name and contract were found. Please check your config and try again.", contractName, configurationName));
                    }

                    cnannelEndPoint = element;
                }

                return cnannelEndPoint;
            }

            /// <summary>
            /// Retrieves configured binding.
            /// </summary>
            /// <param name="bindingSectionName">The binding property in an endpoint configuration element.</param>
            /// <param name="configurationName">The bindingConfiguration property in an endpoint configuration element.</param>
            /// <returns>Retunes configured binding.</returns>
            private Binding LookupBinding(string bindingSectionName, string configurationName)
            {
                if (string.IsNullOrEmpty(bindingSectionName))
                {
                    new ConfigurationErrorsException(
                        "The binding specified cannot be null or an empty string.  Please specify a valid binding.  " +
                        "Valid binding values can be found in the system.serviceModel/extensions/bindingExtensions collection.");
                }

                BindingCollectionElement bindingCollectionElement = this.ConfiguraionContext.Bindings[bindingSectionName];
                Binding binding = (Binding)bindingCollectionElement.GetType().InvokeMember(
                     "GetDefault",
                     BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance,
                     null,
                     bindingCollectionElement,
                     null,
                     CultureInfo.InvariantCulture);

                if (!string.IsNullOrEmpty(configurationName))
                {
                    bool flag = false;
                    foreach (IBindingConfigurationElement bindingConfigElement in bindingCollectionElement.ConfiguredBindings)
                    {
                        if ((bindingConfigElement != null) && bindingConfigElement.Name.Equals(configurationName, StringComparison.Ordinal))
                        {
                            if (resolvedBindings == null)
                            {
                                resolvedBindings = new List<string>();
                            }

                            string item = bindingSectionName + "/" + configurationName;
                            if (resolvedBindings.Contains(item))
                            {
                                ConfigurationElement element3 = (ConfigurationElement)bindingConfigElement;
                                StringBuilder builder = new StringBuilder();
                                foreach (string str2 in resolvedBindings)
                                {
                                    builder = builder.AppendFormat("{0}, ", str2);
                                }

                                builder = builder.Append(item);
                                resolvedBindings = null;

                                throw new ConfigurationErrorsException(string.Format(
                                    "A binding reference cycle was detected in your configuration. The following reference cycle must be removed: {0}.",
                                    builder.ToString(),
                                    element3.ElementInformation.Source,
                                    element3.ElementInformation.LineNumber));
                            }

                            try
                            {
                                ContextInformation context = (ContextInformation)bindingConfigElement.GetType().InvokeMember(
                                    "System.ServiceModel.Configuration.IConfigurationContextProviderInternal.GetOriginalEvaluationContext",
                                     BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance,
                                     null,
                                     bindingConfigElement,
                                     null,
                                     CultureInfo.InvariantCulture);

                                this.CheckAccess(context);

                                resolvedBindings.Add(item);
                                bindingConfigElement.ApplyConfiguration(binding);
                                resolvedBindings.Remove(item);
                            }
                            catch
                            {
                                if (resolvedBindings != null)
                                {
                                    resolvedBindings = null;
                                }

                                throw;
                            }

                            if ((resolvedBindings != null) && (resolvedBindings.Count == 0))
                            {
                                resolvedBindings = null;
                            }

                            flag = true;
                        }
                    }

                    if (!flag)
                    {
                        binding = null;
                    }
                }

                return binding;
            }

            /// <summary>
            /// Checks configuration permissions when accessing configuration above application.
            /// </summary>
            /// <param name="contextInformation">Configuration context information.</param>
            private void CheckAccess(ContextInformation contextInformation)
            {
                if (IsConfigAboveApplication(contextInformation))
                {
                    ConfigurationPermission.Demand();
                }
            }

            /// <summary>
            /// Loads configured identity.
            /// </summary>
            /// <param name="element">Identity configuration element.</param>
            /// <returns>Configured endpoint identity.</returns>
            private EndpointIdentity LoadIdentity(IdentityElement element)
            {
                EndpointIdentity identity = null;
                PropertyInformationCollection properties = element.ElementInformation.Properties;
                if (properties["userPrincipalName"].ValueOrigin != PropertyValueOrigin.Default)
                {
                    return EndpointIdentity.CreateUpnIdentity(element.UserPrincipalName.Value);
                }

                if (properties["servicePrincipalName"].ValueOrigin != PropertyValueOrigin.Default)
                {
                    return EndpointIdentity.CreateSpnIdentity(element.ServicePrincipalName.Value);
                }

                if (properties["dns"].ValueOrigin != PropertyValueOrigin.Default)
                {
                    return EndpointIdentity.CreateDnsIdentity(element.Dns.Value);
                }

                if (properties["rsa"].ValueOrigin != PropertyValueOrigin.Default)
                {
                    return EndpointIdentity.CreateRsaIdentity(element.Rsa.Value);
                }

                if (properties["certificate"].ValueOrigin != PropertyValueOrigin.Default)
                {
                    X509Certificate2Collection supportingCertificates = new X509Certificate2Collection();
                    supportingCertificates.Import(Convert.FromBase64String(element.Certificate.EncodedValue));
                    if (supportingCertificates.Count == 0)
                    {
                        throw new InvalidOperationException("UnableToLoadCertificateIdentity");
                    }

                    X509Certificate2 primaryCertificate = supportingCertificates[0];
                    supportingCertificates.RemoveAt(0);
                    return EndpointIdentity.CreateX509CertificateIdentity(primaryCertificate, supportingCertificates);
                }

                if (properties["certificateReference"].ValueOrigin != PropertyValueOrigin.Default)
                {
                    // TODO: Implement support for certificateReference.
                    throw new NotImplementedException("Support for property 'certificateReference' is not implemented.");

                    ////X509CertificateStore store = new X509CertificateStore(element.CertificateReference.StoreName, element.CertificateReference.StoreLocation);
                    ////X509Certificate2Collection certificates = null;
                    ////try
                    ////{
                    ////    store.Open(OpenFlags.ReadOnly);
                    ////    certificates = store.Find(element.CertificateReference.X509FindType, element.CertificateReference.FindValue, false);
                    ////    if (certificates.Count == 0)
                    ////    {
                    ////        throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new InvalidOperationException(SR.GetString("UnableToLoadCertificateIdentity")));
                    ////    }
                    ////    X509Certificate2 certificate = new X509Certificate2(certificates[0]);
                    ////    if (element.CertificateReference.IsChainIncluded)
                    ////    {
                    ////        X509Chain certificateChain = new X509Chain();
                    ////        certificateChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    ////        certificateChain.Build(certificate);
                    ////        return EndpointIdentity.CreateX509CertificateIdentity(certificateChain);
                    ////    }
                    ////    identity = EndpointIdentity.CreateX509CertificateIdentity(certificate);
                    ////}
                    ////finally
                    ////{
                    ////    SecurityUtils.ResetAllCertificates(certificates);
                    ////    store.Close();
                    ////}
                }

                return identity;
            }

            /// <summary>
            /// Retrieves configured endpoint behaviours.
            /// </summary>
            /// <param name="behaviorName">The name property in an behavior configuration element.</param>
            /// <param name="context">Configuration context.</param>
            /// <returns>Returns configured endpoint behaviour or null if non found.</returns>
            private EndpointBehaviorElement LookupEndpointBehaviors(string behaviorName, ContextInformation context)
            {
                EndpointBehaviorElement element = null;
                if (!string.IsNullOrEmpty(behaviorName))
                {
                    BehaviorsSection section = null;
                    if (context == null)
                    {
                        section = (BehaviorsSection)typeof(BehaviorsSection).InvokeMember(
                             "UnsafeGetSection",
                             BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Static,
                             null,
                             null,
                             null,
                             CultureInfo.InvariantCulture);
                    }
                    else
                    {
                        section = (BehaviorsSection)typeof(BehaviorsSection).InvokeMember(
                             "UnsafeGetAssociatedSection",
                             BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Static,
                             null,
                             null,
                             new object[] { context },
                             CultureInfo.InvariantCulture);
                    }

                    if (section.EndpointBehaviors.ContainsKey(behaviorName))
                    {
                        element = section.EndpointBehaviors[behaviorName];
                    }
                }

                if (element != null)
                {
                    ContextInformation originakContext = (ContextInformation)element.GetType().InvokeMember(
                        "System.ServiceModel.Configuration.IConfigurationContextProviderInternal.GetOriginalEvaluationContext",
                        BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance,
                        null,
                        element,
                        null,
                        CultureInfo.InvariantCulture);

                    this.CheckAccess(originakContext);
                }

                return element;
            }

            /// <summary>
            /// Retrieves common behaviours section.
            /// </summary>
            /// <param name="context">Lookup context.</param>
            /// <returns>Returns configured common behaviour section.</returns>
            private CommonBehaviorsSection LookupCommonBehaviors(ContextInformation context)
            {
                if (context != null)
                {
                    return (CommonBehaviorsSection)typeof(CommonBehaviorsSection).InvokeMember(
                        "UnsafeGetAssociatedSection",
                        BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Static,
                        null,
                        null,
                        new object[] { context },
                        CultureInfo.InvariantCulture);
                }

                return (CommonBehaviorsSection)typeof(CommonBehaviorsSection).InvokeMember(
                    "UnsafeGetSection",
                    BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Static,
                    null,
                    null,
                    null,
                    CultureInfo.InvariantCulture);
            }

            /// <summary>
            /// Loads configured endpoint behaviour.
            /// </summary>
            /// <typeparam name="T"></typeparam>
            /// <param name="behaviorElement">Configured behaviours.</param>
            /// <param name="behaviors">Loaded behaviours.</param>
            /// <param name="commonBehaviors">True if common behaviours are being loaded, false otherwise.</param>
            private void LoadBehaviors<T>(ServiceModelExtensionCollectionElement<BehaviorExtensionElement> behaviorElement, KeyedByTypeCollection<T> behaviors, bool commonBehaviors)
            {
                bool? isPartialTrust = null;
                KeyedByTypeCollection<T> types = new KeyedByTypeCollection<T>();
                for (int i = 0; i < behaviorElement.Count; i++)
                {
                    BehaviorExtensionElement behaviorExtension = behaviorElement[i];
                    object behavior = behaviorExtension.GetType().InvokeMember(
                         "CreateBehavior",
                         BindingFlags.InvokeMethod | BindingFlags.NonPublic | BindingFlags.Instance,
                         null,
                         behaviorExtension,
                         null,
                         CultureInfo.InvariantCulture);

                    if (behavior != null)
                    {
                        Type behavourType = behavior.GetType();
                        if (!typeof(T).IsAssignableFrom(behavourType))
                        {
                            // TODO: Implement the following
                            // TraceBehaviorWarning(behaviorExtension, TraceCode.SkipBehavior, behavourType, typeof(T));
                        }
                        else if (commonBehaviors && ShouldSkipCommonBehavior(behavourType, ref isPartialTrust))
                        {
                            // TODO: Implement the following
                            // TraceBehaviorWarning(behaviorExtension, TraceCode.SkipBehavior, behavourType, typeof(T));
                        }
                        else
                        {
                            types.Add((T)behavior);
                            if (behaviors.Contains(behavourType))
                            {
                                // TODO: Implement the following
                                // TraceBehaviorWarning(behaviorExtension, TraceCode.RemoveBehavior, behavourType, typeof(T));
                                behaviors.Remove(behavourType);
                            }

                            behaviors.Add((T)behavior);
                        }
                    }
                }
            }

            #endregion
        }

        #endregion
    }
}
