// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FusionApps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FusionEnvironmentRefreshActivityArgs extends com.pulumi.resources.ResourceArgs {

    public static final FusionEnvironmentRefreshActivityArgs Empty = new FusionEnvironmentRefreshActivityArgs();

    /**
     * unique FusionEnvironment identifier
     * 
     */
    @Import(name="fusionEnvironmentId", required=true)
    private Output<String> fusionEnvironmentId;

    /**
     * @return unique FusionEnvironment identifier
     * 
     */
    public Output<String> fusionEnvironmentId() {
        return this.fusionEnvironmentId;
    }

    /**
     * Represents if the customer opted for Data Masking or not during refreshActivity.
     * 
     */
    @Import(name="isDataMaskingOpted")
    private @Nullable Output<Boolean> isDataMaskingOpted;

    /**
     * @return Represents if the customer opted for Data Masking or not during refreshActivity.
     * 
     */
    public Optional<Output<Boolean>> isDataMaskingOpted() {
        return Optional.ofNullable(this.isDataMaskingOpted);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
     * 
     */
    @Import(name="sourceFusionEnvironmentId", required=true)
    private Output<String> sourceFusionEnvironmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
     * 
     */
    public Output<String> sourceFusionEnvironmentId() {
        return this.sourceFusionEnvironmentId;
    }

    private FusionEnvironmentRefreshActivityArgs() {}

    private FusionEnvironmentRefreshActivityArgs(FusionEnvironmentRefreshActivityArgs $) {
        this.fusionEnvironmentId = $.fusionEnvironmentId;
        this.isDataMaskingOpted = $.isDataMaskingOpted;
        this.sourceFusionEnvironmentId = $.sourceFusionEnvironmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FusionEnvironmentRefreshActivityArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FusionEnvironmentRefreshActivityArgs $;

        public Builder() {
            $ = new FusionEnvironmentRefreshActivityArgs();
        }

        public Builder(FusionEnvironmentRefreshActivityArgs defaults) {
            $ = new FusionEnvironmentRefreshActivityArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(Output<String> fusionEnvironmentId) {
            $.fusionEnvironmentId = fusionEnvironmentId;
            return this;
        }

        /**
         * @param fusionEnvironmentId unique FusionEnvironment identifier
         * 
         * @return builder
         * 
         */
        public Builder fusionEnvironmentId(String fusionEnvironmentId) {
            return fusionEnvironmentId(Output.of(fusionEnvironmentId));
        }

        /**
         * @param isDataMaskingOpted Represents if the customer opted for Data Masking or not during refreshActivity.
         * 
         * @return builder
         * 
         */
        public Builder isDataMaskingOpted(@Nullable Output<Boolean> isDataMaskingOpted) {
            $.isDataMaskingOpted = isDataMaskingOpted;
            return this;
        }

        /**
         * @param isDataMaskingOpted Represents if the customer opted for Data Masking or not during refreshActivity.
         * 
         * @return builder
         * 
         */
        public Builder isDataMaskingOpted(Boolean isDataMaskingOpted) {
            return isDataMaskingOpted(Output.of(isDataMaskingOpted));
        }

        /**
         * @param sourceFusionEnvironmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
         * 
         * @return builder
         * 
         */
        public Builder sourceFusionEnvironmentId(Output<String> sourceFusionEnvironmentId) {
            $.sourceFusionEnvironmentId = sourceFusionEnvironmentId;
            return this;
        }

        /**
         * @param sourceFusionEnvironmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source environment
         * 
         * @return builder
         * 
         */
        public Builder sourceFusionEnvironmentId(String sourceFusionEnvironmentId) {
            return sourceFusionEnvironmentId(Output.of(sourceFusionEnvironmentId));
        }

        public FusionEnvironmentRefreshActivityArgs build() {
            if ($.fusionEnvironmentId == null) {
                throw new MissingRequiredPropertyException("FusionEnvironmentRefreshActivityArgs", "fusionEnvironmentId");
            }
            if ($.sourceFusionEnvironmentId == null) {
                throw new MissingRequiredPropertyException("FusionEnvironmentRefreshActivityArgs", "sourceFusionEnvironmentId");
            }
            return $;
        }
    }

}
