// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LicenseManager.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTopUtilizedProductLicensesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTopUtilizedProductLicensesArgs Empty = new GetTopUtilizedProductLicensesArgs();

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Indicates if the given compartment is the root compartment.
     * 
     */
    @Import(name="isCompartmentIdInSubtree")
    private @Nullable Output<Boolean> isCompartmentIdInSubtree;

    /**
     * @return Indicates if the given compartment is the root compartment.
     * 
     */
    public Optional<Output<Boolean>> isCompartmentIdInSubtree() {
        return Optional.ofNullable(this.isCompartmentIdInSubtree);
    }

    private GetTopUtilizedProductLicensesArgs() {}

    private GetTopUtilizedProductLicensesArgs(GetTopUtilizedProductLicensesArgs $) {
        this.compartmentId = $.compartmentId;
        this.isCompartmentIdInSubtree = $.isCompartmentIdInSubtree;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTopUtilizedProductLicensesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTopUtilizedProductLicensesArgs $;

        public Builder() {
            $ = new GetTopUtilizedProductLicensesArgs();
        }

        public Builder(GetTopUtilizedProductLicensesArgs defaults) {
            $ = new GetTopUtilizedProductLicensesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) used for the license record, product license, and configuration.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param isCompartmentIdInSubtree Indicates if the given compartment is the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder isCompartmentIdInSubtree(@Nullable Output<Boolean> isCompartmentIdInSubtree) {
            $.isCompartmentIdInSubtree = isCompartmentIdInSubtree;
            return this;
        }

        /**
         * @param isCompartmentIdInSubtree Indicates if the given compartment is the root compartment.
         * 
         * @return builder
         * 
         */
        public Builder isCompartmentIdInSubtree(Boolean isCompartmentIdInSubtree) {
            return isCompartmentIdInSubtree(Output.of(isCompartmentIdInSubtree));
        }

        public GetTopUtilizedProductLicensesArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}