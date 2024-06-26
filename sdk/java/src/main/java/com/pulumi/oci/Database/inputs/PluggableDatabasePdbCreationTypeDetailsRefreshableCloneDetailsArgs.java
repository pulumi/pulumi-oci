// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs Empty = new PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs();

    /**
     * Indicates whether Pluggable Database is a refreshable clone.
     * 
     */
    @Import(name="isRefreshableClone")
    private @Nullable Output<Boolean> isRefreshableClone;

    /**
     * @return Indicates whether Pluggable Database is a refreshable clone.
     * 
     */
    public Optional<Output<Boolean>> isRefreshableClone() {
        return Optional.ofNullable(this.isRefreshableClone);
    }

    private PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs() {}

    private PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs(PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs $) {
        this.isRefreshableClone = $.isRefreshableClone;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs $;

        public Builder() {
            $ = new PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs();
        }

        public Builder(PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs defaults) {
            $ = new PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param isRefreshableClone Indicates whether Pluggable Database is a refreshable clone.
         * 
         * @return builder
         * 
         */
        public Builder isRefreshableClone(@Nullable Output<Boolean> isRefreshableClone) {
            $.isRefreshableClone = isRefreshableClone;
            return this;
        }

        /**
         * @param isRefreshableClone Indicates whether Pluggable Database is a refreshable clone.
         * 
         * @return builder
         * 
         */
        public Builder isRefreshableClone(Boolean isRefreshableClone) {
            return isRefreshableClone(Output.of(isRefreshableClone));
        }

        public PluggableDatabasePdbCreationTypeDetailsRefreshableCloneDetailsArgs build() {
            return $;
        }
    }

}
