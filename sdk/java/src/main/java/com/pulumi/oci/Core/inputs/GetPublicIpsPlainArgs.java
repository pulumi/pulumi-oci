// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetPublicIpsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPublicIpsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPublicIpsPlainArgs Empty = new GetPublicIpsPlainArgs();

    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable String availabilityDomain;

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetPublicIpsFilter> filters;

    public Optional<List<GetPublicIpsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only public IPs that match given lifetime.
     * 
     */
    @Import(name="lifetime")
    private @Nullable String lifetime;

    /**
     * @return A filter to return only public IPs that match given lifetime.
     * 
     */
    public Optional<String> lifetime() {
        return Optional.ofNullable(this.lifetime);
    }

    /**
     * A filter to return only resources that belong to the given public IP pool.
     * 
     */
    @Import(name="publicIpPoolId")
    private @Nullable String publicIpPoolId;

    /**
     * @return A filter to return only resources that belong to the given public IP pool.
     * 
     */
    public Optional<String> publicIpPoolId() {
        return Optional.ofNullable(this.publicIpPoolId);
    }

    /**
     * Whether the public IP is regional or specific to a particular availability domain.
     * * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs have `scope` = `REGION`, as do ephemeral public IPs assigned to a regional entity.
     * * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it&#39;s assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
     * 
     */
    @Import(name="scope", required=true)
    private String scope;

    /**
     * @return Whether the public IP is regional or specific to a particular availability domain.
     * * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs have `scope` = `REGION`, as do ephemeral public IPs assigned to a regional entity.
     * * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it&#39;s assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
     * 
     */
    public String scope() {
        return this.scope;
    }

    private GetPublicIpsPlainArgs() {}

    private GetPublicIpsPlainArgs(GetPublicIpsPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.lifetime = $.lifetime;
        this.publicIpPoolId = $.publicIpPoolId;
        this.scope = $.scope;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPublicIpsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPublicIpsPlainArgs $;

        public Builder() {
            $ = new GetPublicIpsPlainArgs();
        }

        public Builder(GetPublicIpsPlainArgs defaults) {
            $ = new GetPublicIpsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetPublicIpsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetPublicIpsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param lifetime A filter to return only public IPs that match given lifetime.
         * 
         * @return builder
         * 
         */
        public Builder lifetime(@Nullable String lifetime) {
            $.lifetime = lifetime;
            return this;
        }

        /**
         * @param publicIpPoolId A filter to return only resources that belong to the given public IP pool.
         * 
         * @return builder
         * 
         */
        public Builder publicIpPoolId(@Nullable String publicIpPoolId) {
            $.publicIpPoolId = publicIpPoolId;
            return this;
        }

        /**
         * @param scope Whether the public IP is regional or specific to a particular availability domain.
         * * `REGION`: The public IP exists within a region and is assigned to a regional entity (such as a [NatGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NatGateway/)), or can be assigned to a private IP in any availability domain in the region. Reserved public IPs have `scope` = `REGION`, as do ephemeral public IPs assigned to a regional entity.
         * * `AVAILABILITY_DOMAIN`: The public IP exists within the availability domain of the entity it&#39;s assigned to, which is specified by the `availabilityDomain` property of the public IP object. Ephemeral public IPs that are assigned to private IPs have `scope` = `AVAILABILITY_DOMAIN`.
         * 
         * @return builder
         * 
         */
        public Builder scope(String scope) {
            $.scope = scope;
            return this;
        }

        public GetPublicIpsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.scope = Objects.requireNonNull($.scope, "expected parameter 'scope' to be non-null");
            return $;
        }
    }

}