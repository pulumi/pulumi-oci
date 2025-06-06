// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway
{
    public static class GetAddress
    {
        /// <summary>
        /// This data source provides details about a specific Address resource in Oracle Cloud Infrastructure Osp Gateway service.
        /// 
        /// Get the address by id for the compartment
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAddress = Oci.OspGateway.GetAddress.Invoke(new()
        ///     {
        ///         AddressId = testAddres.Id,
        ///         CompartmentId = compartmentId,
        ///         OspHomeRegion = addressOspHomeRegion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAddressResult> InvokeAsync(GetAddressArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAddressResult>("oci:OspGateway/getAddress:getAddress", args ?? new GetAddressArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Address resource in Oracle Cloud Infrastructure Osp Gateway service.
        /// 
        /// Get the address by id for the compartment
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAddress = Oci.OspGateway.GetAddress.Invoke(new()
        ///     {
        ///         AddressId = testAddres.Id,
        ///         CompartmentId = compartmentId,
        ///         OspHomeRegion = addressOspHomeRegion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAddressResult> Invoke(GetAddressInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAddressResult>("oci:OspGateway/getAddress:getAddress", args ?? new GetAddressInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Address resource in Oracle Cloud Infrastructure Osp Gateway service.
        /// 
        /// Get the address by id for the compartment
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAddress = Oci.OspGateway.GetAddress.Invoke(new()
        ///     {
        ///         AddressId = testAddres.Id,
        ///         CompartmentId = compartmentId,
        ///         OspHomeRegion = addressOspHomeRegion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAddressResult> Invoke(GetAddressInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAddressResult>("oci:OspGateway/getAddress:getAddress", args ?? new GetAddressInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAddressArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The identifier of the address.
        /// </summary>
        [Input("addressId", required: true)]
        public string AddressId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The home region's public name of the logged in user.
        /// </summary>
        [Input("ospHomeRegion", required: true)]
        public string OspHomeRegion { get; set; } = null!;

        public GetAddressArgs()
        {
        }
        public static new GetAddressArgs Empty => new GetAddressArgs();
    }

    public sealed class GetAddressInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The identifier of the address.
        /// </summary>
        [Input("addressId", required: true)]
        public Input<string> AddressId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The home region's public name of the logged in user.
        /// </summary>
        [Input("ospHomeRegion", required: true)]
        public Input<string> OspHomeRegion { get; set; } = null!;

        public GetAddressInvokeArgs()
        {
        }
        public static new GetAddressInvokeArgs Empty => new GetAddressInvokeArgs();
    }


    [OutputType]
    public sealed class GetAddressResult
    {
        public readonly string AddressId;
        /// <summary>
        /// Address identifier.
        /// </summary>
        public readonly string AddressKey;
        /// <summary>
        /// Name of the city.
        /// </summary>
        public readonly string City;
        /// <summary>
        /// Name of the customer company.
        /// </summary>
        public readonly string CompanyName;
        public readonly string CompartmentId;
        /// <summary>
        /// Contributor class of the customer company.
        /// </summary>
        public readonly string ContributorClass;
        /// <summary>
        /// Country of the address.
        /// </summary>
        public readonly string Country;
        /// <summary>
        /// County of the address.
        /// </summary>
        public readonly string County;
        /// <summary>
        /// Department name of the customer company.
        /// </summary>
        public readonly string DepartmentName;
        /// <summary>
        /// Contact person email address.
        /// </summary>
        public readonly string EmailAddress;
        /// <summary>
        /// First name of the contact person.
        /// </summary>
        public readonly string FirstName;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Internal number of the customer company.
        /// </summary>
        public readonly string InternalNumber;
        /// <summary>
        /// Job title of the contact person.
        /// </summary>
        public readonly string JobTitle;
        /// <summary>
        /// Last name of the contact person.
        /// </summary>
        public readonly string LastName;
        /// <summary>
        /// Address line 1.
        /// </summary>
        public readonly string Line1;
        /// <summary>
        /// Address line 2.
        /// </summary>
        public readonly string Line2;
        /// <summary>
        /// Address line 3.
        /// </summary>
        public readonly string Line3;
        /// <summary>
        /// Address line 4.
        /// </summary>
        public readonly string Line4;
        /// <summary>
        /// Middle name of the contact person.
        /// </summary>
        public readonly string MiddleName;
        /// <summary>
        /// Municipal Inscription.
        /// </summary>
        public readonly string MunicipalInscription;
        public readonly string OspHomeRegion;
        /// <summary>
        /// Phone country code of the contact person.
        /// </summary>
        public readonly string PhoneCountryCode;
        /// <summary>
        /// Phone number of the contact person.
        /// </summary>
        public readonly string PhoneNumber;
        /// <summary>
        /// Post code of the address.
        /// </summary>
        public readonly string PostalCode;
        /// <summary>
        /// Province of the address.
        /// </summary>
        public readonly string Province;
        /// <summary>
        /// State of the address.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// State Inscription.
        /// </summary>
        public readonly string StateInscription;
        /// <summary>
        /// Street name of the address.
        /// </summary>
        public readonly string StreetName;
        /// <summary>
        /// Street number of the address.
        /// </summary>
        public readonly string StreetNumber;

        [OutputConstructor]
        private GetAddressResult(
            string addressId,

            string addressKey,

            string city,

            string companyName,

            string compartmentId,

            string contributorClass,

            string country,

            string county,

            string departmentName,

            string emailAddress,

            string firstName,

            string id,

            string internalNumber,

            string jobTitle,

            string lastName,

            string line1,

            string line2,

            string line3,

            string line4,

            string middleName,

            string municipalInscription,

            string ospHomeRegion,

            string phoneCountryCode,

            string phoneNumber,

            string postalCode,

            string province,

            string state,

            string stateInscription,

            string streetName,

            string streetNumber)
        {
            AddressId = addressId;
            AddressKey = addressKey;
            City = city;
            CompanyName = companyName;
            CompartmentId = compartmentId;
            ContributorClass = contributorClass;
            Country = country;
            County = county;
            DepartmentName = departmentName;
            EmailAddress = emailAddress;
            FirstName = firstName;
            Id = id;
            InternalNumber = internalNumber;
            JobTitle = jobTitle;
            LastName = lastName;
            Line1 = line1;
            Line2 = line2;
            Line3 = line3;
            Line4 = line4;
            MiddleName = middleName;
            MunicipalInscription = municipalInscription;
            OspHomeRegion = ospHomeRegion;
            PhoneCountryCode = phoneCountryCode;
            PhoneNumber = phoneNumber;
            PostalCode = postalCode;
            Province = province;
            State = state;
            StateInscription = stateInscription;
            StreetName = streetName;
            StreetNumber = streetNumber;
        }
    }
}
