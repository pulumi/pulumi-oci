// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OspGateway.Outputs
{

    [OutputType]
    public sealed class AddressActionVerificationAddress
    {
        /// <summary>
        /// Address identifier.
        /// </summary>
        public readonly string? AddressKey;
        /// <summary>
        /// Name of the city.
        /// </summary>
        public readonly string? City;
        /// <summary>
        /// Name of the customer company.
        /// </summary>
        public readonly string? CompanyName;
        /// <summary>
        /// Contributor class of the customer company.
        /// </summary>
        public readonly string? ContributorClass;
        /// <summary>
        /// Country of the address.
        /// </summary>
        public readonly string? Country;
        /// <summary>
        /// County of the address.
        /// </summary>
        public readonly string? County;
        /// <summary>
        /// Department name of the customer company.
        /// </summary>
        public readonly string? DepartmentName;
        /// <summary>
        /// Contact person email address.
        /// </summary>
        public readonly string? EmailAddress;
        /// <summary>
        /// First name of the contact person.
        /// </summary>
        public readonly string? FirstName;
        /// <summary>
        /// Internal number of the customer company.
        /// </summary>
        public readonly string? InternalNumber;
        /// <summary>
        /// Job title of the contact person.
        /// </summary>
        public readonly string? JobTitle;
        /// <summary>
        /// Last name of the contact person.
        /// </summary>
        public readonly string? LastName;
        /// <summary>
        /// Address line 1.
        /// </summary>
        public readonly string? Line1;
        /// <summary>
        /// Address line 2.
        /// </summary>
        public readonly string? Line2;
        /// <summary>
        /// Address line 3.
        /// </summary>
        public readonly string? Line3;
        /// <summary>
        /// Address line 4.
        /// </summary>
        public readonly string? Line4;
        /// <summary>
        /// Middle name of the contact person.
        /// </summary>
        public readonly string? MiddleName;
        /// <summary>
        /// Municipal Inscription.
        /// </summary>
        public readonly string? MunicipalInscription;
        /// <summary>
        /// Phone country code of the contact person.
        /// </summary>
        public readonly string? PhoneCountryCode;
        /// <summary>
        /// Phone number of the contact person.
        /// </summary>
        public readonly string? PhoneNumber;
        /// <summary>
        /// Post code of the address.
        /// </summary>
        public readonly string? PostalCode;
        /// <summary>
        /// Province of the address.
        /// </summary>
        public readonly string? Province;
        /// <summary>
        /// State of the address.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// State Inscription.
        /// </summary>
        public readonly string? StateInscription;
        /// <summary>
        /// Street name of the address.
        /// </summary>
        public readonly string? StreetName;
        /// <summary>
        /// Street number of the address.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string? StreetNumber;

        [OutputConstructor]
        private AddressActionVerificationAddress(
            string? addressKey,

            string? city,

            string? companyName,

            string? contributorClass,

            string? country,

            string? county,

            string? departmentName,

            string? emailAddress,

            string? firstName,

            string? internalNumber,

            string? jobTitle,

            string? lastName,

            string? line1,

            string? line2,

            string? line3,

            string? line4,

            string? middleName,

            string? municipalInscription,

            string? phoneCountryCode,

            string? phoneNumber,

            string? postalCode,

            string? province,

            string? state,

            string? stateInscription,

            string? streetName,

            string? streetNumber)
        {
            AddressKey = addressKey;
            City = city;
            CompanyName = companyName;
            ContributorClass = contributorClass;
            Country = country;
            County = county;
            DepartmentName = departmentName;
            EmailAddress = emailAddress;
            FirstName = firstName;
            InternalNumber = internalNumber;
            JobTitle = jobTitle;
            LastName = lastName;
            Line1 = line1;
            Line2 = line2;
            Line3 = line3;
            Line4 = line4;
            MiddleName = middleName;
            MunicipalInscription = municipalInscription;
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