// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class FunctionSourceDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final FunctionSourceDetailsArgs Empty = new FunctionSourceDetailsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PbfListing this function is sourced from.
     * 
     */
    @Import(name="pbfListingId", required=true)
    private Output<String> pbfListingId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PbfListing this function is sourced from.
     * 
     */
    public Output<String> pbfListingId() {
        return this.pbfListingId;
    }

    /**
     * Type of the Function Source. Possible values: PRE_BUILT_FUNCTIONS.
     * 
     */
    @Import(name="sourceType", required=true)
    private Output<String> sourceType;

    /**
     * @return Type of the Function Source. Possible values: PRE_BUILT_FUNCTIONS.
     * 
     */
    public Output<String> sourceType() {
        return this.sourceType;
    }

    private FunctionSourceDetailsArgs() {}

    private FunctionSourceDetailsArgs(FunctionSourceDetailsArgs $) {
        this.pbfListingId = $.pbfListingId;
        this.sourceType = $.sourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FunctionSourceDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FunctionSourceDetailsArgs $;

        public Builder() {
            $ = new FunctionSourceDetailsArgs();
        }

        public Builder(FunctionSourceDetailsArgs defaults) {
            $ = new FunctionSourceDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param pbfListingId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PbfListing this function is sourced from.
         * 
         * @return builder
         * 
         */
        public Builder pbfListingId(Output<String> pbfListingId) {
            $.pbfListingId = pbfListingId;
            return this;
        }

        /**
         * @param pbfListingId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PbfListing this function is sourced from.
         * 
         * @return builder
         * 
         */
        public Builder pbfListingId(String pbfListingId) {
            return pbfListingId(Output.of(pbfListingId));
        }

        /**
         * @param sourceType Type of the Function Source. Possible values: PRE_BUILT_FUNCTIONS.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(Output<String> sourceType) {
            $.sourceType = sourceType;
            return this;
        }

        /**
         * @param sourceType Type of the Function Source. Possible values: PRE_BUILT_FUNCTIONS.
         * 
         * @return builder
         * 
         */
        public Builder sourceType(String sourceType) {
            return sourceType(Output.of(sourceType));
        }

        public FunctionSourceDetailsArgs build() {
            if ($.pbfListingId == null) {
                throw new MissingRequiredPropertyException("FunctionSourceDetailsArgs", "pbfListingId");
            }
            if ($.sourceType == null) {
                throw new MissingRequiredPropertyException("FunctionSourceDetailsArgs", "sourceType");
            }
            return $;
        }
    }

}
