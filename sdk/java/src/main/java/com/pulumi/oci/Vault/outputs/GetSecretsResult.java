// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Vault.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Vault.outputs.GetSecretsFilter;
import com.pulumi.oci.Vault.outputs.GetSecretsSecret;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSecretsResult {
    /**
     * @return The OCID of the compartment where you want to create the secret.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetSecretsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String name;
    /**
     * @return The list of secrets.
     * 
     */
    private List<GetSecretsSecret> secrets;
    /**
     * @return The current lifecycle state of the secret.
     * 
     */
    private @Nullable String state;
    /**
     * @return The OCID of the Vault in which the secret exists
     * 
     */
    private @Nullable String vaultId;

    private GetSecretsResult() {}
    /**
     * @return The OCID of the compartment where you want to create the secret.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetSecretsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The list of secrets.
     * 
     */
    public List<GetSecretsSecret> secrets() {
        return this.secrets;
    }
    /**
     * @return The current lifecycle state of the secret.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The OCID of the Vault in which the secret exists
     * 
     */
    public Optional<String> vaultId() {
        return Optional.ofNullable(this.vaultId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSecretsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetSecretsFilter> filters;
        private String id;
        private @Nullable String name;
        private List<GetSecretsSecret> secrets;
        private @Nullable String state;
        private @Nullable String vaultId;
        public Builder() {}
        public Builder(GetSecretsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.secrets = defaults.secrets;
    	      this.state = defaults.state;
    	      this.vaultId = defaults.vaultId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSecretsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSecretsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder secrets(List<GetSecretsSecret> secrets) {
            this.secrets = Objects.requireNonNull(secrets);
            return this;
        }
        public Builder secrets(GetSecretsSecret... secrets) {
            return secrets(List.of(secrets));
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder vaultId(@Nullable String vaultId) {
            this.vaultId = vaultId;
            return this;
        }
        public GetSecretsResult build() {
            final var o = new GetSecretsResult();
            o.compartmentId = compartmentId;
            o.filters = filters;
            o.id = id;
            o.name = name;
            o.secrets = secrets;
            o.state = state;
            o.vaultId = vaultId;
            return o;
        }
    }
}