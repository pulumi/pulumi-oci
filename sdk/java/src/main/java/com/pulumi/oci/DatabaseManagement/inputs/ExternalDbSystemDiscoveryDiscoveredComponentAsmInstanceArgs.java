// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs Empty = new ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs();

    /**
     * The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    @Import(name="adrHomeDirectory")
    private @Nullable Output<String> adrHomeDirectory;

    /**
     * @return The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
     * 
     */
    public Optional<Output<String>> adrHomeDirectory() {
        return Optional.ofNullable(this.adrHomeDirectory);
    }

    /**
     * The host name of the database or the SCAN name in case of a RAC database.
     * 
     */
    @Import(name="hostName")
    private @Nullable Output<String> hostName;

    /**
     * @return The host name of the database or the SCAN name in case of a RAC database.
     * 
     */
    public Optional<Output<String>> hostName() {
        return Optional.ofNullable(this.hostName);
    }

    /**
     * The name of the ASM instance.
     * 
     */
    @Import(name="instanceName")
    private @Nullable Output<String> instanceName;

    /**
     * @return The name of the ASM instance.
     * 
     */
    public Optional<Output<String>> instanceName() {
        return Optional.ofNullable(this.instanceName);
    }

    private ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs() {}

    private ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs(ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs $) {
        this.adrHomeDirectory = $.adrHomeDirectory;
        this.hostName = $.hostName;
        this.instanceName = $.instanceName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs $;

        public Builder() {
            $ = new ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs();
        }

        public Builder(ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs defaults) {
            $ = new ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param adrHomeDirectory The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder adrHomeDirectory(@Nullable Output<String> adrHomeDirectory) {
            $.adrHomeDirectory = adrHomeDirectory;
            return this;
        }

        /**
         * @param adrHomeDirectory The Automatic Diagnostic Repository (ADR) home directory for the cluster instance.
         * 
         * @return builder
         * 
         */
        public Builder adrHomeDirectory(String adrHomeDirectory) {
            return adrHomeDirectory(Output.of(adrHomeDirectory));
        }

        /**
         * @param hostName The host name of the database or the SCAN name in case of a RAC database.
         * 
         * @return builder
         * 
         */
        public Builder hostName(@Nullable Output<String> hostName) {
            $.hostName = hostName;
            return this;
        }

        /**
         * @param hostName The host name of the database or the SCAN name in case of a RAC database.
         * 
         * @return builder
         * 
         */
        public Builder hostName(String hostName) {
            return hostName(Output.of(hostName));
        }

        /**
         * @param instanceName The name of the ASM instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceName(@Nullable Output<String> instanceName) {
            $.instanceName = instanceName;
            return this;
        }

        /**
         * @param instanceName The name of the ASM instance.
         * 
         * @return builder
         * 
         */
        public Builder instanceName(String instanceName) {
            return instanceName(Output.of(instanceName));
        }

        public ExternalDbSystemDiscoveryDiscoveredComponentAsmInstanceArgs build() {
            return $;
        }
    }

}