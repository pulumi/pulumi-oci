// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ManagedInstanceAutonomouseArgs extends com.pulumi.resources.ResourceArgs {

    public static final ManagedInstanceAutonomouseArgs Empty = new ManagedInstanceAutonomouseArgs();

    /**
     * True if daily updates are enabled
     * 
     */
    @Import(name="isAutoUpdateEnabled")
    private @Nullable Output<Boolean> isAutoUpdateEnabled;

    /**
     * @return True if daily updates are enabled
     * 
     */
    public Optional<Output<Boolean>> isAutoUpdateEnabled() {
        return Optional.ofNullable(this.isAutoUpdateEnabled);
    }

    private ManagedInstanceAutonomouseArgs() {}

    private ManagedInstanceAutonomouseArgs(ManagedInstanceAutonomouseArgs $) {
        this.isAutoUpdateEnabled = $.isAutoUpdateEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ManagedInstanceAutonomouseArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ManagedInstanceAutonomouseArgs $;

        public Builder() {
            $ = new ManagedInstanceAutonomouseArgs();
        }

        public Builder(ManagedInstanceAutonomouseArgs defaults) {
            $ = new ManagedInstanceAutonomouseArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isAutoUpdateEnabled True if daily updates are enabled
         * 
         * @return builder
         * 
         */
        public Builder isAutoUpdateEnabled(@Nullable Output<Boolean> isAutoUpdateEnabled) {
            $.isAutoUpdateEnabled = isAutoUpdateEnabled;
            return this;
        }

        /**
         * @param isAutoUpdateEnabled True if daily updates are enabled
         * 
         * @return builder
         * 
         */
        public Builder isAutoUpdateEnabled(Boolean isAutoUpdateEnabled) {
            return isAutoUpdateEnabled(Output.of(isAutoUpdateEnabled));
        }

        public ManagedInstanceAutonomouseArgs build() {
            return $;
        }
    }

}
