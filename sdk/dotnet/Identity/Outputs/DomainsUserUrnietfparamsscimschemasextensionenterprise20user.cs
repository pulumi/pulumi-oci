// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsUserUrnietfparamsscimschemasextensionenterprise20user
    {
        /// <summary>
        /// (Updatable) Identifies the name of a cost center.
        /// </summary>
        public readonly string? CostCenter;
        /// <summary>
        /// (Updatable) Identifies the name of a department.
        /// </summary>
        public readonly string? Department;
        /// <summary>
        /// (Updatable) Identifies the name of a division.
        /// </summary>
        public readonly string? Division;
        /// <summary>
        /// (Updatable) Numeric or alphanumeric identifier assigned to  a person, typically based on order of hire or association with an organization.
        /// </summary>
        public readonly string? EmployeeNumber;
        /// <summary>
        /// (Updatable) The User's manager. A complex type that optionally allows Service Providers to represent organizational hierarchy by referencing the 'id' attribute of another User.
        /// </summary>
        public readonly Outputs.DomainsUserUrnietfparamsscimschemasextensionenterprise20userManager? Manager;
        /// <summary>
        /// (Updatable) Identifies the name of an organization.
        /// </summary>
        public readonly string? Organization;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasextensionenterprise20user(
            string? costCenter,

            string? department,

            string? division,

            string? employeeNumber,

            Outputs.DomainsUserUrnietfparamsscimschemasextensionenterprise20userManager? manager,

            string? organization)
        {
            CostCenter = costCenter;
            Department = department;
            Division = division;
            EmployeeNumber = employeeNumber;
            Manager = manager;
            Organization = organization;
        }
    }
}