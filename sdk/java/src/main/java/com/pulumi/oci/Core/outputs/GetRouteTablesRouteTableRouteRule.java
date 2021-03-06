// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetRouteTablesRouteTableRouteRule {
    /**
     * @return Deprecated. Instead use `destination` and `destinationType`. Requests that include both `cidrBlock` and `destination` will be rejected.
     * 
     * @deprecated
     * The &#39;cidr_block&#39; field has been deprecated. Please use &#39;destination&#39; instead.
     * 
     */
    @Deprecated /* The 'cidr_block' field has been deprecated. Please use 'destination' instead. */
    private final String cidrBlock;
    /**
     * @return An optional description of your choice for the rule.
     * 
     */
    private final String description;
    /**
     * @return Conceptually, this is the range of IP addresses used for matching when routing traffic. Required if you provide a `destinationType`.
     * 
     */
    private final String destination;
    /**
     * @return Type of destination for the rule. Required if you provide a `destination`.
     * * `CIDR_BLOCK`: If the rule&#39;s `destination` is an IP address range in CIDR notation.
     * * `SERVICE_CIDR_BLOCK`: If the rule&#39;s `destination` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic destined for a particular `Service` through a service gateway).
     * 
     */
    private final String destinationType;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the route rule&#39;s target. For information about the type of targets you can specify, see [Route Tables](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm).
     * 
     */
    private final String networkEntityId;

    @CustomType.Constructor
    private GetRouteTablesRouteTableRouteRule(
        @CustomType.Parameter("cidrBlock") String cidrBlock,
        @CustomType.Parameter("description") String description,
        @CustomType.Parameter("destination") String destination,
        @CustomType.Parameter("destinationType") String destinationType,
        @CustomType.Parameter("networkEntityId") String networkEntityId) {
        this.cidrBlock = cidrBlock;
        this.description = description;
        this.destination = destination;
        this.destinationType = destinationType;
        this.networkEntityId = networkEntityId;
    }

    /**
     * @return Deprecated. Instead use `destination` and `destinationType`. Requests that include both `cidrBlock` and `destination` will be rejected.
     * 
     * @deprecated
     * The &#39;cidr_block&#39; field has been deprecated. Please use &#39;destination&#39; instead.
     * 
     */
    @Deprecated /* The 'cidr_block' field has been deprecated. Please use 'destination' instead. */
    public String cidrBlock() {
        return this.cidrBlock;
    }
    /**
     * @return An optional description of your choice for the rule.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return Conceptually, this is the range of IP addresses used for matching when routing traffic. Required if you provide a `destinationType`.
     * 
     */
    public String destination() {
        return this.destination;
    }
    /**
     * @return Type of destination for the rule. Required if you provide a `destination`.
     * * `CIDR_BLOCK`: If the rule&#39;s `destination` is an IP address range in CIDR notation.
     * * `SERVICE_CIDR_BLOCK`: If the rule&#39;s `destination` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic destined for a particular `Service` through a service gateway).
     * 
     */
    public String destinationType() {
        return this.destinationType;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the route rule&#39;s target. For information about the type of targets you can specify, see [Route Tables](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm).
     * 
     */
    public String networkEntityId() {
        return this.networkEntityId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRouteTablesRouteTableRouteRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String cidrBlock;
        private String description;
        private String destination;
        private String destinationType;
        private String networkEntityId;

        public Builder() {
    	      // Empty
        }

        public Builder(GetRouteTablesRouteTableRouteRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cidrBlock = defaults.cidrBlock;
    	      this.description = defaults.description;
    	      this.destination = defaults.destination;
    	      this.destinationType = defaults.destinationType;
    	      this.networkEntityId = defaults.networkEntityId;
        }

        public Builder cidrBlock(String cidrBlock) {
            this.cidrBlock = Objects.requireNonNull(cidrBlock);
            return this;
        }
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        public Builder destination(String destination) {
            this.destination = Objects.requireNonNull(destination);
            return this;
        }
        public Builder destinationType(String destinationType) {
            this.destinationType = Objects.requireNonNull(destinationType);
            return this;
        }
        public Builder networkEntityId(String networkEntityId) {
            this.networkEntityId = Objects.requireNonNull(networkEntityId);
            return this;
        }        public GetRouteTablesRouteTableRouteRule build() {
            return new GetRouteTablesRouteTableRouteRule(cidrBlock, description, destination, destinationType, networkEntityId);
        }
    }
}
