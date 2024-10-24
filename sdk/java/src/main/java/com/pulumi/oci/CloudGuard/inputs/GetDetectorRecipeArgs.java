// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDetectorRecipeArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDetectorRecipeArgs Empty = new GetDetectorRecipeArgs();

    /**
     * Detector recipe OCID
     * 
     */
    @Import(name="detectorRecipeId", required=true)
    private Output<String> detectorRecipeId;

    /**
     * @return Detector recipe OCID
     * 
     */
    public Output<String> detectorRecipeId() {
        return this.detectorRecipeId;
    }

    private GetDetectorRecipeArgs() {}

    private GetDetectorRecipeArgs(GetDetectorRecipeArgs $) {
        this.detectorRecipeId = $.detectorRecipeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDetectorRecipeArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDetectorRecipeArgs $;

        public Builder() {
            $ = new GetDetectorRecipeArgs();
        }

        public Builder(GetDetectorRecipeArgs defaults) {
            $ = new GetDetectorRecipeArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param detectorRecipeId Detector recipe OCID
         * 
         * @return builder
         * 
         */
        public Builder detectorRecipeId(Output<String> detectorRecipeId) {
            $.detectorRecipeId = detectorRecipeId;
            return this;
        }

        /**
         * @param detectorRecipeId Detector recipe OCID
         * 
         * @return builder
         * 
         */
        public Builder detectorRecipeId(String detectorRecipeId) {
            return detectorRecipeId(Output.of(detectorRecipeId));
        }

        public GetDetectorRecipeArgs build() {
            if ($.detectorRecipeId == null) {
                throw new MissingRequiredPropertyException("GetDetectorRecipeArgs", "detectorRecipeId");
            }
            return $;
        }
    }

}
