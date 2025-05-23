// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Tenantmanagercontrolplane.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOrganizationPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOrganizationPlainArgs Empty = new GetOrganizationPlainArgs();

    /**
     * OCID of the organization to retrieve.
     * 
     */
    @Import(name="organizationId", required=true)
    private String organizationId;

    /**
     * @return OCID of the organization to retrieve.
     * 
     */
    public String organizationId() {
        return this.organizationId;
    }

    private GetOrganizationPlainArgs() {}

    private GetOrganizationPlainArgs(GetOrganizationPlainArgs $) {
        this.organizationId = $.organizationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOrganizationPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOrganizationPlainArgs $;

        public Builder() {
            $ = new GetOrganizationPlainArgs();
        }

        public Builder(GetOrganizationPlainArgs defaults) {
            $ = new GetOrganizationPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param organizationId OCID of the organization to retrieve.
         * 
         * @return builder
         * 
         */
        public Builder organizationId(String organizationId) {
            $.organizationId = organizationId;
            return this;
        }

        public GetOrganizationPlainArgs build() {
            if ($.organizationId == null) {
                throw new MissingRequiredPropertyException("GetOrganizationPlainArgs", "organizationId");
            }
            return $;
        }
    }

}
