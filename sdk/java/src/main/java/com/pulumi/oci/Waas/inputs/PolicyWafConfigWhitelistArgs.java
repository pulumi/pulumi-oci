// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PolicyWafConfigWhitelistArgs extends com.pulumi.resources.ResourceArgs {

    public static final PolicyWafConfigWhitelistArgs Empty = new PolicyWafConfigWhitelistArgs();

    /**
     * (Updatable) A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of IP address lists to include in the whitelist.
     * 
     */
    @Import(name="addressLists")
    private @Nullable Output<List<String>> addressLists;

    /**
     * @return (Updatable) A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of IP address lists to include in the whitelist.
     * 
     */
    public Optional<Output<List<String>>> addressLists() {
        return Optional.ofNullable(this.addressLists);
    }

    /**
     * (Updatable) A set of IP addresses or CIDR notations to include in the whitelist.
     * 
     */
    @Import(name="addresses")
    private @Nullable Output<List<String>> addresses;

    /**
     * @return (Updatable) A set of IP addresses or CIDR notations to include in the whitelist.
     * 
     */
    public Optional<Output<List<String>>> addresses() {
        return Optional.ofNullable(this.addresses);
    }

    /**
     * (Updatable) The unique name of the whitelist.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) The unique name of the whitelist.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    private PolicyWafConfigWhitelistArgs() {}

    private PolicyWafConfigWhitelistArgs(PolicyWafConfigWhitelistArgs $) {
        this.addressLists = $.addressLists;
        this.addresses = $.addresses;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PolicyWafConfigWhitelistArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PolicyWafConfigWhitelistArgs $;

        public Builder() {
            $ = new PolicyWafConfigWhitelistArgs();
        }

        public Builder(PolicyWafConfigWhitelistArgs defaults) {
            $ = new PolicyWafConfigWhitelistArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param addressLists (Updatable) A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of IP address lists to include in the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder addressLists(@Nullable Output<List<String>> addressLists) {
            $.addressLists = addressLists;
            return this;
        }

        /**
         * @param addressLists (Updatable) A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of IP address lists to include in the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder addressLists(List<String> addressLists) {
            return addressLists(Output.of(addressLists));
        }

        /**
         * @param addressLists (Updatable) A list of [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of IP address lists to include in the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder addressLists(String... addressLists) {
            return addressLists(List.of(addressLists));
        }

        /**
         * @param addresses (Updatable) A set of IP addresses or CIDR notations to include in the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder addresses(@Nullable Output<List<String>> addresses) {
            $.addresses = addresses;
            return this;
        }

        /**
         * @param addresses (Updatable) A set of IP addresses or CIDR notations to include in the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder addresses(List<String> addresses) {
            return addresses(Output.of(addresses));
        }

        /**
         * @param addresses (Updatable) A set of IP addresses or CIDR notations to include in the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder addresses(String... addresses) {
            return addresses(List.of(addresses));
        }

        /**
         * @param name (Updatable) The unique name of the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The unique name of the whitelist.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public PolicyWafConfigWhitelistArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            return $;
        }
    }

}