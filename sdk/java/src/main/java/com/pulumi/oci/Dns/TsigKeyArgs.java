// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class TsigKeyArgs extends com.pulumi.resources.ResourceArgs {

    public static final TsigKeyArgs Empty = new TsigKeyArgs();

    /**
     * TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
     * 
     */
    @Import(name="algorithm", required=true)
    private Output<String> algorithm;

    /**
     * @return TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
     * 
     */
    public Output<String> algorithm() {
        return this.algorithm;
    }

    /**
     * (Updatable) The OCID of the compartment containing the TSIG key.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment containing the TSIG key.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * A globally unique domain name identifying the key for a given pair of hosts.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A globally unique domain name identifying the key for a given pair of hosts.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A base64 string encoding the binary shared secret.
     * 
     */
    @Import(name="secret", required=true)
    private Output<String> secret;

    /**
     * @return A base64 string encoding the binary shared secret.
     * 
     */
    public Output<String> secret() {
        return this.secret;
    }

    private TsigKeyArgs() {}

    private TsigKeyArgs(TsigKeyArgs $) {
        this.algorithm = $.algorithm;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.name = $.name;
        this.secret = $.secret;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(TsigKeyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private TsigKeyArgs $;

        public Builder() {
            $ = new TsigKeyArgs();
        }

        public Builder(TsigKeyArgs defaults) {
            $ = new TsigKeyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param algorithm TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
         * 
         * @return builder
         * 
         */
        public Builder algorithm(Output<String> algorithm) {
            $.algorithm = algorithm;
            return this;
        }

        /**
         * @param algorithm TSIG key algorithms are encoded as domain names, but most consist of only one non-empty label, which is not required to be explicitly absolute. Applicable algorithms include: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha512. For more information on these algorithms, see [RFC 4635](https://tools.ietf.org/html/rfc4635#section-2).
         * 
         * @return builder
         * 
         */
        public Builder algorithm(String algorithm) {
            return algorithm(Output.of(algorithm));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the TSIG key.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment containing the TSIG key.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param name A globally unique domain name identifying the key for a given pair of hosts.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A globally unique domain name identifying the key for a given pair of hosts.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param secret A base64 string encoding the binary shared secret.
         * 
         * @return builder
         * 
         */
        public Builder secret(Output<String> secret) {
            $.secret = secret;
            return this;
        }

        /**
         * @param secret A base64 string encoding the binary shared secret.
         * 
         * @return builder
         * 
         */
        public Builder secret(String secret) {
            return secret(Output.of(secret));
        }

        public TsigKeyArgs build() {
            $.algorithm = Objects.requireNonNull($.algorithm, "expected parameter 'algorithm' to be non-null");
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.secret = Objects.requireNonNull($.secret, "expected parameter 'secret' to be non-null");
            return $;
        }
    }

}
