// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetResolversResolverRule {
    private final String action;
    private final List<String> clientAddressConditions;
    private final List<String> destinationAddresses;
    private final List<String> qnameCoverConditions;
    private final String sourceEndpointName;

    @CustomType.Constructor
    private GetResolversResolverRule(
        @CustomType.Parameter("action") String action,
        @CustomType.Parameter("clientAddressConditions") List<String> clientAddressConditions,
        @CustomType.Parameter("destinationAddresses") List<String> destinationAddresses,
        @CustomType.Parameter("qnameCoverConditions") List<String> qnameCoverConditions,
        @CustomType.Parameter("sourceEndpointName") String sourceEndpointName) {
        this.action = action;
        this.clientAddressConditions = clientAddressConditions;
        this.destinationAddresses = destinationAddresses;
        this.qnameCoverConditions = qnameCoverConditions;
        this.sourceEndpointName = sourceEndpointName;
    }

    public String action() {
        return this.action;
    }
    public List<String> clientAddressConditions() {
        return this.clientAddressConditions;
    }
    public List<String> destinationAddresses() {
        return this.destinationAddresses;
    }
    public List<String> qnameCoverConditions() {
        return this.qnameCoverConditions;
    }
    public String sourceEndpointName() {
        return this.sourceEndpointName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetResolversResolverRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String action;
        private List<String> clientAddressConditions;
        private List<String> destinationAddresses;
        private List<String> qnameCoverConditions;
        private String sourceEndpointName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetResolversResolverRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.clientAddressConditions = defaults.clientAddressConditions;
    	      this.destinationAddresses = defaults.destinationAddresses;
    	      this.qnameCoverConditions = defaults.qnameCoverConditions;
    	      this.sourceEndpointName = defaults.sourceEndpointName;
        }

        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        public Builder clientAddressConditions(List<String> clientAddressConditions) {
            this.clientAddressConditions = Objects.requireNonNull(clientAddressConditions);
            return this;
        }
        public Builder clientAddressConditions(String... clientAddressConditions) {
            return clientAddressConditions(List.of(clientAddressConditions));
        }
        public Builder destinationAddresses(List<String> destinationAddresses) {
            this.destinationAddresses = Objects.requireNonNull(destinationAddresses);
            return this;
        }
        public Builder destinationAddresses(String... destinationAddresses) {
            return destinationAddresses(List.of(destinationAddresses));
        }
        public Builder qnameCoverConditions(List<String> qnameCoverConditions) {
            this.qnameCoverConditions = Objects.requireNonNull(qnameCoverConditions);
            return this;
        }
        public Builder qnameCoverConditions(String... qnameCoverConditions) {
            return qnameCoverConditions(List.of(qnameCoverConditions));
        }
        public Builder sourceEndpointName(String sourceEndpointName) {
            this.sourceEndpointName = Objects.requireNonNull(sourceEndpointName);
            return this;
        }        public GetResolversResolverRule build() {
            return new GetResolversResolverRule(action, clientAddressConditions, destinationAddresses, qnameCoverConditions, sourceEndpointName);
        }
    }
}
