// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetNamespaceResult {
    private @Nullable String compartmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return (Computed) The name of the user&#39;s namespace.
     * 
     */
    private String namespace;

    private GetNamespaceResult() {}
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return (Computed) The name of the user&#39;s namespace.
     * 
     */
    public String namespace() {
        return this.namespace;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNamespaceResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private String id;
        private String namespace;
        public Builder() {}
        public Builder(GetNamespaceResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.namespace = defaults.namespace;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetNamespaceResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            if (namespace == null) {
              throw new MissingRequiredPropertyException("GetNamespaceResult", "namespace");
            }
            this.namespace = namespace;
            return this;
        }
        public GetNamespaceResult build() {
            final var _resultValue = new GetNamespaceResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.id = id;
            _resultValue.namespace = namespace;
            return _resultValue;
        }
    }
}
