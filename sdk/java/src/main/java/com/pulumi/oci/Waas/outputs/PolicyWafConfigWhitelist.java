// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class PolicyWafConfigWhitelist {
    /**
     * @return (Updatable) A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of IP address lists to include in the whitelist.
     * 
     */
    private final @Nullable List<String> addressLists;
    /**
     * @return (Updatable) A set of IP addresses or CIDR notations to include in the whitelist.
     * 
     */
    private final @Nullable List<String> addresses;
    /**
     * @return (Updatable) The unique name of the whitelist.
     * 
     */
    private final String name;

    @CustomType.Constructor
    private PolicyWafConfigWhitelist(
        @CustomType.Parameter("addressLists") @Nullable List<String> addressLists,
        @CustomType.Parameter("addresses") @Nullable List<String> addresses,
        @CustomType.Parameter("name") String name) {
        this.addressLists = addressLists;
        this.addresses = addresses;
        this.name = name;
    }

    /**
     * @return (Updatable) A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of IP address lists to include in the whitelist.
     * 
     */
    public List<String> addressLists() {
        return this.addressLists == null ? List.of() : this.addressLists;
    }
    /**
     * @return (Updatable) A set of IP addresses or CIDR notations to include in the whitelist.
     * 
     */
    public List<String> addresses() {
        return this.addresses == null ? List.of() : this.addresses;
    }
    /**
     * @return (Updatable) The unique name of the whitelist.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PolicyWafConfigWhitelist defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<String> addressLists;
        private @Nullable List<String> addresses;
        private String name;

        public Builder() {
    	      // Empty
        }

        public Builder(PolicyWafConfigWhitelist defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.addressLists = defaults.addressLists;
    	      this.addresses = defaults.addresses;
    	      this.name = defaults.name;
        }

        public Builder addressLists(@Nullable List<String> addressLists) {
            this.addressLists = addressLists;
            return this;
        }
        public Builder addressLists(String... addressLists) {
            return addressLists(List.of(addressLists));
        }
        public Builder addresses(@Nullable List<String> addresses) {
            this.addresses = addresses;
            return this;
        }
        public Builder addresses(String... addresses) {
            return addresses(List.of(addresses));
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }        public PolicyWafConfigWhitelist build() {
            return new PolicyWafConfigWhitelist(addressLists, addresses, name);
        }
    }
}
