// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.inputs.GetSystemVersionsFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSystemVersionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSystemVersionsArgs Empty = new GetSystemVersionsArgs();

    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetSystemVersionsFilterArgs>> filters;

    public Optional<Output<List<GetSystemVersionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Specifies gi version query parameter.
     * 
     */
    @Import(name="giVersion", required=true)
    private Output<String> giVersion;

    /**
     * @return Specifies gi version query parameter.
     * 
     */
    public Output<String> giVersion() {
        return this.giVersion;
    }

    /**
     * If provided, return highest versions from each major version family.
     * 
     */
    @Import(name="isLatest")
    private @Nullable Output<Boolean> isLatest;

    /**
     * @return If provided, return highest versions from each major version family.
     * 
     */
    public Optional<Output<Boolean>> isLatest() {
        return Optional.ofNullable(this.isLatest);
    }

    /**
     * If provided, filters the results for the specified resource Id.
     * 
     */
    @Import(name="resourceId")
    private @Nullable Output<String> resourceId;

    /**
     * @return If provided, filters the results for the specified resource Id.
     * 
     */
    public Optional<Output<String>> resourceId() {
        return Optional.ofNullable(this.resourceId);
    }

    /**
     * If provided, filters the results for the given shape.
     * 
     */
    @Import(name="shape")
    private @Nullable Output<String> shape;

    /**
     * @return If provided, filters the results for the given shape.
     * 
     */
    public Optional<Output<String>> shape() {
        return Optional.ofNullable(this.shape);
    }

    private GetSystemVersionsArgs() {}

    private GetSystemVersionsArgs(GetSystemVersionsArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.giVersion = $.giVersion;
        this.isLatest = $.isLatest;
        this.resourceId = $.resourceId;
        this.shape = $.shape;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSystemVersionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSystemVersionsArgs $;

        public Builder() {
            $ = new GetSystemVersionsArgs();
        }

        public Builder(GetSystemVersionsArgs defaults) {
            $ = new GetSystemVersionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetSystemVersionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSystemVersionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSystemVersionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param giVersion Specifies gi version query parameter.
         * 
         * @return builder
         * 
         */
        public Builder giVersion(Output<String> giVersion) {
            $.giVersion = giVersion;
            return this;
        }

        /**
         * @param giVersion Specifies gi version query parameter.
         * 
         * @return builder
         * 
         */
        public Builder giVersion(String giVersion) {
            return giVersion(Output.of(giVersion));
        }

        /**
         * @param isLatest If provided, return highest versions from each major version family.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(@Nullable Output<Boolean> isLatest) {
            $.isLatest = isLatest;
            return this;
        }

        /**
         * @param isLatest If provided, return highest versions from each major version family.
         * 
         * @return builder
         * 
         */
        public Builder isLatest(Boolean isLatest) {
            return isLatest(Output.of(isLatest));
        }

        /**
         * @param resourceId If provided, filters the results for the specified resource Id.
         * 
         * @return builder
         * 
         */
        public Builder resourceId(@Nullable Output<String> resourceId) {
            $.resourceId = resourceId;
            return this;
        }

        /**
         * @param resourceId If provided, filters the results for the specified resource Id.
         * 
         * @return builder
         * 
         */
        public Builder resourceId(String resourceId) {
            return resourceId(Output.of(resourceId));
        }

        /**
         * @param shape If provided, filters the results for the given shape.
         * 
         * @return builder
         * 
         */
        public Builder shape(@Nullable Output<String> shape) {
            $.shape = shape;
            return this;
        }

        /**
         * @param shape If provided, filters the results for the given shape.
         * 
         * @return builder
         * 
         */
        public Builder shape(String shape) {
            return shape(Output.of(shape));
        }

        public GetSystemVersionsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetSystemVersionsArgs", "compartmentId");
            }
            if ($.giVersion == null) {
                throw new MissingRequiredPropertyException("GetSystemVersionsArgs", "giVersion");
            }
            return $;
        }
    }

}
