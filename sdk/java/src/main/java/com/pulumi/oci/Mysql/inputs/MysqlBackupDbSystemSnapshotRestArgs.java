// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class MysqlBackupDbSystemSnapshotRestArgs extends com.pulumi.resources.ResourceArgs {

    public static final MysqlBackupDbSystemSnapshotRestArgs Empty = new MysqlBackupDbSystemSnapshotRestArgs();

    /**
     * Select how REST is configured across the DB System instances.
     * 
     */
    @Import(name="configuration")
    private @Nullable Output<String> configuration;

    /**
     * @return Select how REST is configured across the DB System instances.
     * 
     */
    public Optional<Output<String>> configuration() {
        return Optional.ofNullable(this.configuration);
    }

    /**
     * The port for REST to listen on. Supported port numbers are 443 and from 1024 to 65535.
     * 
     */
    @Import(name="port")
    private @Nullable Output<Integer> port;

    /**
     * @return The port for REST to listen on. Supported port numbers are 443 and from 1024 to 65535.
     * 
     */
    public Optional<Output<Integer>> port() {
        return Optional.ofNullable(this.port);
    }

    private MysqlBackupDbSystemSnapshotRestArgs() {}

    private MysqlBackupDbSystemSnapshotRestArgs(MysqlBackupDbSystemSnapshotRestArgs $) {
        this.configuration = $.configuration;
        this.port = $.port;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(MysqlBackupDbSystemSnapshotRestArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private MysqlBackupDbSystemSnapshotRestArgs $;

        public Builder() {
            $ = new MysqlBackupDbSystemSnapshotRestArgs();
        }

        public Builder(MysqlBackupDbSystemSnapshotRestArgs defaults) {
            $ = new MysqlBackupDbSystemSnapshotRestArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param configuration Select how REST is configured across the DB System instances.
         * 
         * @return builder
         * 
         */
        public Builder configuration(@Nullable Output<String> configuration) {
            $.configuration = configuration;
            return this;
        }

        /**
         * @param configuration Select how REST is configured across the DB System instances.
         * 
         * @return builder
         * 
         */
        public Builder configuration(String configuration) {
            return configuration(Output.of(configuration));
        }

        /**
         * @param port The port for REST to listen on. Supported port numbers are 443 and from 1024 to 65535.
         * 
         * @return builder
         * 
         */
        public Builder port(@Nullable Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port The port for REST to listen on. Supported port numbers are 443 and from 1024 to 65535.
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        public MysqlBackupDbSystemSnapshotRestArgs build() {
            return $;
        }
    }

}
