// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Redis;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RedisClusterCreateIdentityTokenArgs extends com.pulumi.resources.ResourceArgs {

    public static final RedisClusterCreateIdentityTokenArgs Empty = new RedisClusterCreateIdentityTokenArgs();

    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * User public key pair
     * 
     */
    @Import(name="publicKey", required=true)
    private Output<String> publicKey;

    /**
     * @return User public key pair
     * 
     */
    public Output<String> publicKey() {
        return this.publicKey;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     * 
     */
    @Import(name="redisClusterId", required=true)
    private Output<String> redisClusterId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
     * 
     */
    public Output<String> redisClusterId() {
        return this.redisClusterId;
    }

    /**
     * Redis User generating identity token.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="redisUser", required=true)
    private Output<String> redisUser;

    /**
     * @return Redis User generating identity token.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> redisUser() {
        return this.redisUser;
    }

    private RedisClusterCreateIdentityTokenArgs() {}

    private RedisClusterCreateIdentityTokenArgs(RedisClusterCreateIdentityTokenArgs $) {
        this.definedTags = $.definedTags;
        this.freeformTags = $.freeformTags;
        this.publicKey = $.publicKey;
        this.redisClusterId = $.redisClusterId;
        this.redisUser = $.redisUser;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RedisClusterCreateIdentityTokenArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RedisClusterCreateIdentityTokenArgs $;

        public Builder() {
            $ = new RedisClusterCreateIdentityTokenArgs();
        }

        public Builder(RedisClusterCreateIdentityTokenArgs defaults) {
            $ = new RedisClusterCreateIdentityTokenArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param freeformTags Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param publicKey User public key pair
         * 
         * @return builder
         * 
         */
        public Builder publicKey(Output<String> publicKey) {
            $.publicKey = publicKey;
            return this;
        }

        /**
         * @param publicKey User public key pair
         * 
         * @return builder
         * 
         */
        public Builder publicKey(String publicKey) {
            return publicKey(Output.of(publicKey));
        }

        /**
         * @param redisClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder redisClusterId(Output<String> redisClusterId) {
            $.redisClusterId = redisClusterId;
            return this;
        }

        /**
         * @param redisClusterId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm#Oracle) of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder redisClusterId(String redisClusterId) {
            return redisClusterId(Output.of(redisClusterId));
        }

        /**
         * @param redisUser Redis User generating identity token.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder redisUser(Output<String> redisUser) {
            $.redisUser = redisUser;
            return this;
        }

        /**
         * @param redisUser Redis User generating identity token.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder redisUser(String redisUser) {
            return redisUser(Output.of(redisUser));
        }

        public RedisClusterCreateIdentityTokenArgs build() {
            if ($.publicKey == null) {
                throw new MissingRequiredPropertyException("RedisClusterCreateIdentityTokenArgs", "publicKey");
            }
            if ($.redisClusterId == null) {
                throw new MissingRequiredPropertyException("RedisClusterCreateIdentityTokenArgs", "redisClusterId");
            }
            if ($.redisUser == null) {
                throw new MissingRequiredPropertyException("RedisClusterCreateIdentityTokenArgs", "redisUser");
            }
            return $;
        }
    }

}
