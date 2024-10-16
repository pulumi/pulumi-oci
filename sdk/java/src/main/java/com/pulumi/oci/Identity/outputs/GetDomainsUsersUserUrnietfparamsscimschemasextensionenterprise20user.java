// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20userManager;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user {
    /**
     * @return Identifies the name of a cost center.
     * 
     */
    private String costCenter;
    /**
     * @return Identifies the name of a department.
     * 
     */
    private String department;
    /**
     * @return Identifies the name of a division.
     * 
     */
    private String division;
    /**
     * @return Numeric or alphanumeric identifier assigned to  a person, typically based on order of hire or association with an organization.
     * 
     */
    private String employeeNumber;
    /**
     * @return The User&#39;s manager. A complex type that optionally allows Service Providers to represent organizational hierarchy by referencing the &#39;id&#39; attribute of another User.
     * 
     */
    private List<GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20userManager> managers;
    /**
     * @return Identifies the name of an organization.
     * 
     */
    private String organization;

    private GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user() {}
    /**
     * @return Identifies the name of a cost center.
     * 
     */
    public String costCenter() {
        return this.costCenter;
    }
    /**
     * @return Identifies the name of a department.
     * 
     */
    public String department() {
        return this.department;
    }
    /**
     * @return Identifies the name of a division.
     * 
     */
    public String division() {
        return this.division;
    }
    /**
     * @return Numeric or alphanumeric identifier assigned to  a person, typically based on order of hire or association with an organization.
     * 
     */
    public String employeeNumber() {
        return this.employeeNumber;
    }
    /**
     * @return The User&#39;s manager. A complex type that optionally allows Service Providers to represent organizational hierarchy by referencing the &#39;id&#39; attribute of another User.
     * 
     */
    public List<GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20userManager> managers() {
        return this.managers;
    }
    /**
     * @return Identifies the name of an organization.
     * 
     */
    public String organization() {
        return this.organization;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String costCenter;
        private String department;
        private String division;
        private String employeeNumber;
        private List<GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20userManager> managers;
        private String organization;
        public Builder() {}
        public Builder(GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.costCenter = defaults.costCenter;
    	      this.department = defaults.department;
    	      this.division = defaults.division;
    	      this.employeeNumber = defaults.employeeNumber;
    	      this.managers = defaults.managers;
    	      this.organization = defaults.organization;
        }

        @CustomType.Setter
        public Builder costCenter(String costCenter) {
            if (costCenter == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user", "costCenter");
            }
            this.costCenter = costCenter;
            return this;
        }
        @CustomType.Setter
        public Builder department(String department) {
            if (department == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user", "department");
            }
            this.department = department;
            return this;
        }
        @CustomType.Setter
        public Builder division(String division) {
            if (division == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user", "division");
            }
            this.division = division;
            return this;
        }
        @CustomType.Setter
        public Builder employeeNumber(String employeeNumber) {
            if (employeeNumber == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user", "employeeNumber");
            }
            this.employeeNumber = employeeNumber;
            return this;
        }
        @CustomType.Setter
        public Builder managers(List<GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20userManager> managers) {
            if (managers == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user", "managers");
            }
            this.managers = managers;
            return this;
        }
        public Builder managers(GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20userManager... managers) {
            return managers(List.of(managers));
        }
        @CustomType.Setter
        public Builder organization(String organization) {
            if (organization == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user", "organization");
            }
            this.organization = organization;
            return this;
        }
        public GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user build() {
            final var _resultValue = new GetDomainsUsersUserUrnietfparamsscimschemasextensionenterprise20user();
            _resultValue.costCenter = costCenter;
            _resultValue.department = department;
            _resultValue.division = division;
            _resultValue.employeeNumber = employeeNumber;
            _resultValue.managers = managers;
            _resultValue.organization = organization;
            return _resultValue;
        }
    }
}
