// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Dns.outputs.GetTsigKeysFilter;
import com.pulumi.oci.Dns.outputs.GetTsigKeysTsigKey;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetTsigKeysResult {
    /**
     * @return The OCID of the compartment containing the TSIG key.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetTsigKeysFilter> filters;
    /**
     * @return The OCID of the resource.
     * 
     */
    private @Nullable String id;
    /**
     * @return A globally unique domain name identifying the key for a given pair of hosts.
     * 
     */
    private @Nullable String name;
    /**
     * @return The current state of the resource.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of tsig_keys.
     * 
     */
    private List<GetTsigKeysTsigKey> tsigKeys;

    private GetTsigKeysResult() {}
    /**
     * @return The OCID of the compartment containing the TSIG key.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetTsigKeysFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the resource.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return A globally unique domain name identifying the key for a given pair of hosts.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The current state of the resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of tsig_keys.
     * 
     */
    public List<GetTsigKeysTsigKey> tsigKeys() {
        return this.tsigKeys;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTsigKeysResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetTsigKeysFilter> filters;
        private @Nullable String id;
        private @Nullable String name;
        private @Nullable String state;
        private List<GetTsigKeysTsigKey> tsigKeys;
        public Builder() {}
        public Builder(GetTsigKeysResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.state = defaults.state;
    	      this.tsigKeys = defaults.tsigKeys;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetTsigKeysFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetTsigKeysFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder tsigKeys(List<GetTsigKeysTsigKey> tsigKeys) {
            this.tsigKeys = Objects.requireNonNull(tsigKeys);
            return this;
        }
        public Builder tsigKeys(GetTsigKeysTsigKey... tsigKeys) {
            return tsigKeys(List.of(tsigKeys));
        }
        public GetTsigKeysResult build() {
            final var o = new GetTsigKeysResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.name = name;
            o.state = state;
            o.tsigKeys = tsigKeys;
            return o;
        }
    }
}