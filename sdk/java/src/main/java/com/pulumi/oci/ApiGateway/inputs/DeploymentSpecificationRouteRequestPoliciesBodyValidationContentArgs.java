// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs Empty = new DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs();

    /**
     * (Updatable) The media_type is a [media type range](https://tools.ietf.org/html/rfc7231#appendix-D) subset restricted to the following schema
     * 
     */
    @Import(name="mediaType", required=true)
    private Output<String> mediaType;

    /**
     * @return (Updatable) The media_type is a [media type range](https://tools.ietf.org/html/rfc7231#appendix-D) subset restricted to the following schema
     * 
     */
    public Output<String> mediaType() {
        return this.mediaType;
    }

    /**
     * (Updatable) Validation type defines the content validation method.
     * 
     */
    @Import(name="validationType", required=true)
    private Output<String> validationType;

    /**
     * @return (Updatable) Validation type defines the content validation method.
     * 
     */
    public Output<String> validationType() {
        return this.validationType;
    }

    private DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs() {}

    private DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs(DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs $) {
        this.mediaType = $.mediaType;
        this.validationType = $.validationType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs();
        }

        public Builder(DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs defaults) {
            $ = new DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param mediaType (Updatable) The media_type is a [media type range](https://tools.ietf.org/html/rfc7231#appendix-D) subset restricted to the following schema
         * 
         * @return builder
         * 
         */
        public Builder mediaType(Output<String> mediaType) {
            $.mediaType = mediaType;
            return this;
        }

        /**
         * @param mediaType (Updatable) The media_type is a [media type range](https://tools.ietf.org/html/rfc7231#appendix-D) subset restricted to the following schema
         * 
         * @return builder
         * 
         */
        public Builder mediaType(String mediaType) {
            return mediaType(Output.of(mediaType));
        }

        /**
         * @param validationType (Updatable) Validation type defines the content validation method.
         * 
         * @return builder
         * 
         */
        public Builder validationType(Output<String> validationType) {
            $.validationType = validationType;
            return this;
        }

        /**
         * @param validationType (Updatable) Validation type defines the content validation method.
         * 
         * @return builder
         * 
         */
        public Builder validationType(String validationType) {
            return validationType(Output.of(validationType));
        }

        public DeploymentSpecificationRouteRequestPoliciesBodyValidationContentArgs build() {
            $.mediaType = Objects.requireNonNull($.mediaType, "expected parameter 'mediaType' to be non-null");
            $.validationType = Objects.requireNonNull($.validationType, "expected parameter 'validationType' to be non-null");
            return $;
        }
    }

}
