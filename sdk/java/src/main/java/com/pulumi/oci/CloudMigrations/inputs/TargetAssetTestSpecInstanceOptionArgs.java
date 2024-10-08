// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudMigrations.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TargetAssetTestSpecInstanceOptionArgs extends com.pulumi.resources.ResourceArgs {

    public static final TargetAssetTestSpecInstanceOptionArgs Empty = new TargetAssetTestSpecInstanceOptionArgs();

    /**
     * Whether to disable the legacy (/v1) instance metadata service endpoints. Customers who have migrated to /v2 should set this to true for added security. Default is false.
     * 
     */
    @Import(name="areLegacyImdsEndpointsDisabled")
    private @Nullable Output<Boolean> areLegacyImdsEndpointsDisabled;

    /**
     * @return Whether to disable the legacy (/v1) instance metadata service endpoints. Customers who have migrated to /v2 should set this to true for added security. Default is false.
     * 
     */
    public Optional<Output<Boolean>> areLegacyImdsEndpointsDisabled() {
        return Optional.ofNullable(this.areLegacyImdsEndpointsDisabled);
    }

    private TargetAssetTestSpecInstanceOptionArgs() {}

    private TargetAssetTestSpecInstanceOptionArgs(TargetAssetTestSpecInstanceOptionArgs $) {
        this.areLegacyImdsEndpointsDisabled = $.areLegacyImdsEndpointsDisabled;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TargetAssetTestSpecInstanceOptionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TargetAssetTestSpecInstanceOptionArgs $;

        public Builder() {
            $ = new TargetAssetTestSpecInstanceOptionArgs();
        }

        public Builder(TargetAssetTestSpecInstanceOptionArgs defaults) {
            $ = new TargetAssetTestSpecInstanceOptionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param areLegacyImdsEndpointsDisabled Whether to disable the legacy (/v1) instance metadata service endpoints. Customers who have migrated to /v2 should set this to true for added security. Default is false.
         * 
         * @return builder
         * 
         */
        public Builder areLegacyImdsEndpointsDisabled(@Nullable Output<Boolean> areLegacyImdsEndpointsDisabled) {
            $.areLegacyImdsEndpointsDisabled = areLegacyImdsEndpointsDisabled;
            return this;
        }

        /**
         * @param areLegacyImdsEndpointsDisabled Whether to disable the legacy (/v1) instance metadata service endpoints. Customers who have migrated to /v2 should set this to true for added security. Default is false.
         * 
         * @return builder
         * 
         */
        public Builder areLegacyImdsEndpointsDisabled(Boolean areLegacyImdsEndpointsDisabled) {
            return areLegacyImdsEndpointsDisabled(Output.of(areLegacyImdsEndpointsDisabled));
        }

        public TargetAssetTestSpecInstanceOptionArgs build() {
            return $;
        }
    }

}
