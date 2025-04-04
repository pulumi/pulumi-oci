// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs Empty = new AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs();

    /**
     * Region in which adhoc query needs to be run
     * 
     */
    @Import(name="region")
    private @Nullable Output<String> region;

    /**
     * @return Region in which adhoc query needs to be run
     * 
     */
    public Optional<Output<String>> region() {
        return Optional.ofNullable(this.region);
    }

    /**
     * List of OCIDs on which query needs to be run
     * 
     */
    @Import(name="resourceIds")
    private @Nullable Output<List<String>> resourceIds;

    /**
     * @return List of OCIDs on which query needs to be run
     * 
     */
    public Optional<Output<List<String>>> resourceIds() {
        return Optional.ofNullable(this.resourceIds);
    }

    /**
     * Type of resource
     * 
     */
    @Import(name="resourceType")
    private @Nullable Output<String> resourceType;

    /**
     * @return Type of resource
     * 
     */
    public Optional<Output<String>> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }

    private AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs() {}

    private AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs(AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs $) {
        this.region = $.region;
        this.resourceIds = $.resourceIds;
        this.resourceType = $.resourceType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs $;

        public Builder() {
            $ = new AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs();
        }

        public Builder(AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs defaults) {
            $ = new AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param region Region in which adhoc query needs to be run
         * 
         * @return builder
         * 
         */
        public Builder region(@Nullable Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region Region in which adhoc query needs to be run
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        /**
         * @param resourceIds List of OCIDs on which query needs to be run
         * 
         * @return builder
         * 
         */
        public Builder resourceIds(@Nullable Output<List<String>> resourceIds) {
            $.resourceIds = resourceIds;
            return this;
        }

        /**
         * @param resourceIds List of OCIDs on which query needs to be run
         * 
         * @return builder
         * 
         */
        public Builder resourceIds(List<String> resourceIds) {
            return resourceIds(Output.of(resourceIds));
        }

        /**
         * @param resourceIds List of OCIDs on which query needs to be run
         * 
         * @return builder
         * 
         */
        public Builder resourceIds(String... resourceIds) {
            return resourceIds(List.of(resourceIds));
        }

        /**
         * @param resourceType Type of resource
         * 
         * @return builder
         * 
         */
        public Builder resourceType(@Nullable Output<String> resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param resourceType Type of resource
         * 
         * @return builder
         * 
         */
        public Builder resourceType(String resourceType) {
            return resourceType(Output.of(resourceType));
        }

        public AdhocQueryAdhocQueryDetailsAdhocQueryResourceArgs build() {
            return $;
        }
    }

}
