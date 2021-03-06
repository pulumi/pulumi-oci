// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseMigration.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDumpTransferDetailsSourceArgs;
import com.pulumi.oci.DatabaseMigration.inputs.MigrationDumpTransferDetailsTargetArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MigrationDumpTransferDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final MigrationDumpTransferDetailsArgs Empty = new MigrationDumpTransferDetailsArgs();

    /**
     * (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    @Import(name="source")
    private @Nullable Output<MigrationDumpTransferDetailsSourceArgs> source;

    /**
     * @return (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    public Optional<Output<MigrationDumpTransferDetailsSourceArgs>> source() {
        return Optional.ofNullable(this.source);
    }

    /**
     * (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    @Import(name="target")
    private @Nullable Output<MigrationDumpTransferDetailsTargetArgs> target;

    /**
     * @return (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
     * 
     */
    public Optional<Output<MigrationDumpTransferDetailsTargetArgs>> target() {
        return Optional.ofNullable(this.target);
    }

    private MigrationDumpTransferDetailsArgs() {}

    private MigrationDumpTransferDetailsArgs(MigrationDumpTransferDetailsArgs $) {
        this.source = $.source;
        this.target = $.target;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MigrationDumpTransferDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MigrationDumpTransferDetailsArgs $;

        public Builder() {
            $ = new MigrationDumpTransferDetailsArgs();
        }

        public Builder(MigrationDumpTransferDetailsArgs defaults) {
            $ = new MigrationDumpTransferDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param source (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
         * 
         * @return builder
         * 
         */
        public Builder source(@Nullable Output<MigrationDumpTransferDetailsSourceArgs> source) {
            $.source = source;
            return this;
        }

        /**
         * @param source (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
         * 
         * @return builder
         * 
         */
        public Builder source(MigrationDumpTransferDetailsSourceArgs source) {
            return source(Output.of(source));
        }

        /**
         * @param target (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
         * 
         * @return builder
         * 
         */
        public Builder target(@Nullable Output<MigrationDumpTransferDetailsTargetArgs> target) {
            $.target = target;
            return this;
        }

        /**
         * @param target (Updatable) Optional additional properties for dump transfer in source or target host. Default kind is CURL
         * 
         * @return builder
         * 
         */
        public Builder target(MigrationDumpTransferDetailsTargetArgs target) {
            return target(Output.of(target));
        }

        public MigrationDumpTransferDetailsArgs build() {
            return $;
        }
    }

}
