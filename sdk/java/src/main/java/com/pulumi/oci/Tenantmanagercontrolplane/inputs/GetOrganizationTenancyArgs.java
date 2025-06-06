// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOrganizationTenancyArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOrganizationTenancyArgs Empty = new GetOrganizationTenancyArgs();

    /**
     * OCID of the organization.
     * 
     */
    @Import(name="organizationId", required=true)
    private Output<String> organizationId;

    /**
     * @return OCID of the organization.
     * 
     */
    public Output<String> organizationId() {
        return this.organizationId;
    }

    /**
     * OCID of the tenancy to retrieve.
     * 
     */
    @Import(name="tenancyId", required=true)
    private Output<String> tenancyId;

    /**
     * @return OCID of the tenancy to retrieve.
     * 
     */
    public Output<String> tenancyId() {
        return this.tenancyId;
    }

    private GetOrganizationTenancyArgs() {}

    private GetOrganizationTenancyArgs(GetOrganizationTenancyArgs $) {
        this.organizationId = $.organizationId;
        this.tenancyId = $.tenancyId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOrganizationTenancyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOrganizationTenancyArgs $;

        public Builder() {
            $ = new GetOrganizationTenancyArgs();
        }

        public Builder(GetOrganizationTenancyArgs defaults) {
            $ = new GetOrganizationTenancyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param organizationId OCID of the organization.
         * 
         * @return builder
         * 
         */
        public Builder organizationId(Output<String> organizationId) {
            $.organizationId = organizationId;
            return this;
        }

        /**
         * @param organizationId OCID of the organization.
         * 
         * @return builder
         * 
         */
        public Builder organizationId(String organizationId) {
            return organizationId(Output.of(organizationId));
        }

        /**
         * @param tenancyId OCID of the tenancy to retrieve.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(Output<String> tenancyId) {
            $.tenancyId = tenancyId;
            return this;
        }

        /**
         * @param tenancyId OCID of the tenancy to retrieve.
         * 
         * @return builder
         * 
         */
        public Builder tenancyId(String tenancyId) {
            return tenancyId(Output.of(tenancyId));
        }

        public GetOrganizationTenancyArgs build() {
            if ($.organizationId == null) {
                throw new MissingRequiredPropertyException("GetOrganizationTenancyArgs", "organizationId");
            }
            if ($.tenancyId == null) {
                throw new MissingRequiredPropertyException("GetOrganizationTenancyArgs", "tenancyId");
            }
            return $;
        }
    }

}
