// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class EkmsPrivateEndpointArgs extends com.pulumi.resources.ResourceArgs {

    public static final EkmsPrivateEndpointArgs Empty = new EkmsPrivateEndpointArgs();

    /**
     * CABundle to validate TLS certificate of the external key manager system in PEM format
     * 
     */
    @Import(name="caBundle", required=true)
    private Output<String> caBundle;

    /**
     * @return CABundle to validate TLS certificate of the external key manager system in PEM format
     * 
     */
    public Output<String> caBundle() {
        return this.caBundle;
    }

    /**
     * Compartment identifier.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return Compartment identifier.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Display name of the EKMS private endpoint resource being created.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Display name of the EKMS private endpoint resource being created.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * External private IP to connect to from this EKMS private endpoint
     * 
     */
    @Import(name="externalKeyManagerIp", required=true)
    private Output<String> externalKeyManagerIp;

    /**
     * @return External private IP to connect to from this EKMS private endpoint
     * 
     */
    public Output<String> externalKeyManagerIp() {
        return this.externalKeyManagerIp;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The port of the external key manager system
     * 
     */
    @Import(name="port")
    private @Nullable Output<Integer> port;

    /**
     * @return The port of the external key manager system
     * 
     */
    public Optional<Output<Integer>> port() {
        return Optional.ofNullable(this.port);
    }

    /**
     * The OCID of subnet in which the EKMS private endpoint is to be created
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="subnetId", required=true)
    private Output<String> subnetId;

    /**
     * @return The OCID of subnet in which the EKMS private endpoint is to be created
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }

    private EkmsPrivateEndpointArgs() {}

    private EkmsPrivateEndpointArgs(EkmsPrivateEndpointArgs $) {
        this.caBundle = $.caBundle;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.externalKeyManagerIp = $.externalKeyManagerIp;
        this.freeformTags = $.freeformTags;
        this.port = $.port;
        this.subnetId = $.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(EkmsPrivateEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private EkmsPrivateEndpointArgs $;

        public Builder() {
            $ = new EkmsPrivateEndpointArgs();
        }

        public Builder(EkmsPrivateEndpointArgs defaults) {
            $ = new EkmsPrivateEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param caBundle CABundle to validate TLS certificate of the external key manager system in PEM format
         * 
         * @return builder
         * 
         */
        public Builder caBundle(Output<String> caBundle) {
            $.caBundle = caBundle;
            return this;
        }

        /**
         * @param caBundle CABundle to validate TLS certificate of the external key manager system in PEM format
         * 
         * @return builder
         * 
         */
        public Builder caBundle(String caBundle) {
            return caBundle(Output.of(caBundle));
        }

        /**
         * @param compartmentId Compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId Compartment identifier.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Display name of the EKMS private endpoint resource being created.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Display name of the EKMS private endpoint resource being created.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param externalKeyManagerIp External private IP to connect to from this EKMS private endpoint
         * 
         * @return builder
         * 
         */
        public Builder externalKeyManagerIp(Output<String> externalKeyManagerIp) {
            $.externalKeyManagerIp = externalKeyManagerIp;
            return this;
        }

        /**
         * @param externalKeyManagerIp External private IP to connect to from this EKMS private endpoint
         * 
         * @return builder
         * 
         */
        public Builder externalKeyManagerIp(String externalKeyManagerIp) {
            return externalKeyManagerIp(Output.of(externalKeyManagerIp));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param port The port of the external key manager system
         * 
         * @return builder
         * 
         */
        public Builder port(@Nullable Output<Integer> port) {
            $.port = port;
            return this;
        }

        /**
         * @param port The port of the external key manager system
         * 
         * @return builder
         * 
         */
        public Builder port(Integer port) {
            return port(Output.of(port));
        }

        /**
         * @param subnetId The OCID of subnet in which the EKMS private endpoint is to be created
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(Output<String> subnetId) {
            $.subnetId = subnetId;
            return this;
        }

        /**
         * @param subnetId The OCID of subnet in which the EKMS private endpoint is to be created
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder subnetId(String subnetId) {
            return subnetId(Output.of(subnetId));
        }

        public EkmsPrivateEndpointArgs build() {
            $.caBundle = Objects.requireNonNull($.caBundle, "expected parameter 'caBundle' to be non-null");
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.externalKeyManagerIp = Objects.requireNonNull($.externalKeyManagerIp, "expected parameter 'externalKeyManagerIp' to be non-null");
            $.subnetId = Objects.requireNonNull($.subnetId, "expected parameter 'subnetId' to be non-null");
            return $;
        }
    }

}