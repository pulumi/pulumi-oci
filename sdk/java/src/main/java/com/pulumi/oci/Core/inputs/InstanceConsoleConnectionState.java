// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstanceConsoleConnectionState extends com.pulumi.resources.ResourceArgs {

    public static final InstanceConsoleConnectionState Empty = new InstanceConsoleConnectionState();

    /**
     * The OCID of the compartment to contain the console connection.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment to contain the console connection.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * The SSH connection string for the console connection.
     * 
     */
    @Import(name="connectionString")
    private @Nullable Output<String> connectionString;

    /**
     * @return The SSH connection string for the console connection.
     * 
     */
    public Optional<Output<String>> connectionString() {
        return Optional.ofNullable(this.connectionString);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The SSH public key&#39;s fingerprint for client authentication to the console connection.
     * 
     */
    @Import(name="fingerprint")
    private @Nullable Output<String> fingerprint;

    /**
     * @return The SSH public key&#39;s fingerprint for client authentication to the console connection.
     * 
     */
    public Optional<Output<String>> fingerprint() {
        return Optional.ofNullable(this.fingerprint);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The OCID of the instance to create the console connection to.
     * 
     */
    @Import(name="instanceId")
    private @Nullable Output<String> instanceId;

    /**
     * @return The OCID of the instance to create the console connection to.
     * 
     */
    public Optional<Output<String>> instanceId() {
        return Optional.ofNullable(this.instanceId);
    }

    /**
     * The SSH public key used to authenticate the console connection.
     * 
     */
    @Import(name="publicKey")
    private @Nullable Output<String> publicKey;

    /**
     * @return The SSH public key used to authenticate the console connection.
     * 
     */
    public Optional<Output<String>> publicKey() {
        return Optional.ofNullable(this.publicKey);
    }

    /**
     * The SSH public key&#39;s fingerprint for the console connection service host.
     * 
     */
    @Import(name="serviceHostKeyFingerprint")
    private @Nullable Output<String> serviceHostKeyFingerprint;

    /**
     * @return The SSH public key&#39;s fingerprint for the console connection service host.
     * 
     */
    public Optional<Output<String>> serviceHostKeyFingerprint() {
        return Optional.ofNullable(this.serviceHostKeyFingerprint);
    }

    /**
     * The current state of the console connection.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the console connection.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The SSH connection string for the SSH tunnel used to connect to the console connection over VNC.
     * 
     */
    @Import(name="vncConnectionString")
    private @Nullable Output<String> vncConnectionString;

    /**
     * @return The SSH connection string for the SSH tunnel used to connect to the console connection over VNC.
     * 
     */
    public Optional<Output<String>> vncConnectionString() {
        return Optional.ofNullable(this.vncConnectionString);
    }

    private InstanceConsoleConnectionState() {}

    private InstanceConsoleConnectionState(InstanceConsoleConnectionState $) {
        this.compartmentId = $.compartmentId;
        this.connectionString = $.connectionString;
        this.definedTags = $.definedTags;
        this.fingerprint = $.fingerprint;
        this.freeformTags = $.freeformTags;
        this.instanceId = $.instanceId;
        this.publicKey = $.publicKey;
        this.serviceHostKeyFingerprint = $.serviceHostKeyFingerprint;
        this.state = $.state;
        this.vncConnectionString = $.vncConnectionString;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstanceConsoleConnectionState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstanceConsoleConnectionState $;

        public Builder() {
            $ = new InstanceConsoleConnectionState();
        }

        public Builder(InstanceConsoleConnectionState defaults) {
            $ = new InstanceConsoleConnectionState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment to contain the console connection.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment to contain the console connection.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param connectionString The SSH connection string for the console connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(@Nullable Output<String> connectionString) {
            $.connectionString = connectionString;
            return this;
        }

        /**
         * @param connectionString The SSH connection string for the console connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(String connectionString) {
            return connectionString(Output.of(connectionString));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param fingerprint The SSH public key&#39;s fingerprint for client authentication to the console connection.
         * 
         * @return builder
         * 
         */
        public Builder fingerprint(@Nullable Output<String> fingerprint) {
            $.fingerprint = fingerprint;
            return this;
        }

        /**
         * @param fingerprint The SSH public key&#39;s fingerprint for client authentication to the console connection.
         * 
         * @return builder
         * 
         */
        public Builder fingerprint(String fingerprint) {
            return fingerprint(Output.of(fingerprint));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param instanceId The OCID of the instance to create the console connection to.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(@Nullable Output<String> instanceId) {
            $.instanceId = instanceId;
            return this;
        }

        /**
         * @param instanceId The OCID of the instance to create the console connection to.
         * 
         * @return builder
         * 
         */
        public Builder instanceId(String instanceId) {
            return instanceId(Output.of(instanceId));
        }

        /**
         * @param publicKey The SSH public key used to authenticate the console connection.
         * 
         * @return builder
         * 
         */
        public Builder publicKey(@Nullable Output<String> publicKey) {
            $.publicKey = publicKey;
            return this;
        }

        /**
         * @param publicKey The SSH public key used to authenticate the console connection.
         * 
         * @return builder
         * 
         */
        public Builder publicKey(String publicKey) {
            return publicKey(Output.of(publicKey));
        }

        /**
         * @param serviceHostKeyFingerprint The SSH public key&#39;s fingerprint for the console connection service host.
         * 
         * @return builder
         * 
         */
        public Builder serviceHostKeyFingerprint(@Nullable Output<String> serviceHostKeyFingerprint) {
            $.serviceHostKeyFingerprint = serviceHostKeyFingerprint;
            return this;
        }

        /**
         * @param serviceHostKeyFingerprint The SSH public key&#39;s fingerprint for the console connection service host.
         * 
         * @return builder
         * 
         */
        public Builder serviceHostKeyFingerprint(String serviceHostKeyFingerprint) {
            return serviceHostKeyFingerprint(Output.of(serviceHostKeyFingerprint));
        }

        /**
         * @param state The current state of the console connection.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the console connection.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param vncConnectionString The SSH connection string for the SSH tunnel used to connect to the console connection over VNC.
         * 
         * @return builder
         * 
         */
        public Builder vncConnectionString(@Nullable Output<String> vncConnectionString) {
            $.vncConnectionString = vncConnectionString;
            return this;
        }

        /**
         * @param vncConnectionString The SSH connection string for the SSH tunnel used to connect to the console connection over VNC.
         * 
         * @return builder
         * 
         */
        public Builder vncConnectionString(String vncConnectionString) {
            return vncConnectionString(Output.of(vncConnectionString));
        }

        public InstanceConsoleConnectionState build() {
            return $;
        }
    }

}