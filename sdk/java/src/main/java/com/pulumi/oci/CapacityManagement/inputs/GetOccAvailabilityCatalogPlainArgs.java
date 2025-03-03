// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetOccAvailabilityCatalogPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetOccAvailabilityCatalogPlainArgs Empty = new GetOccAvailabilityCatalogPlainArgs();

    /**
     * The OCID of the availability catalog.
     * 
     */
    @Import(name="occAvailabilityCatalogId", required=true)
    private String occAvailabilityCatalogId;

    /**
     * @return The OCID of the availability catalog.
     * 
     */
    public String occAvailabilityCatalogId() {
        return this.occAvailabilityCatalogId;
    }

    private GetOccAvailabilityCatalogPlainArgs() {}

    private GetOccAvailabilityCatalogPlainArgs(GetOccAvailabilityCatalogPlainArgs $) {
        this.occAvailabilityCatalogId = $.occAvailabilityCatalogId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetOccAvailabilityCatalogPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetOccAvailabilityCatalogPlainArgs $;

        public Builder() {
            $ = new GetOccAvailabilityCatalogPlainArgs();
        }

        public Builder(GetOccAvailabilityCatalogPlainArgs defaults) {
            $ = new GetOccAvailabilityCatalogPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param occAvailabilityCatalogId The OCID of the availability catalog.
         * 
         * @return builder
         * 
         */
        public Builder occAvailabilityCatalogId(String occAvailabilityCatalogId) {
            $.occAvailabilityCatalogId = occAvailabilityCatalogId;
            return this;
        }

        public GetOccAvailabilityCatalogPlainArgs build() {
            if ($.occAvailabilityCatalogId == null) {
                throw new MissingRequiredPropertyException("GetOccAvailabilityCatalogPlainArgs", "occAvailabilityCatalogId");
            }
            return $;
        }
    }

}
