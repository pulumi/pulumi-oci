// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTag {
    /**
     * @return The tag key.
     * 
     */
    private String key;
    /**
     * @return The tag namespace.
     * 
     */
    private String namespace;
    /**
     * @return The tag value.
     * 
     */
    private String value;

    private GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTag() {}
    /**
     * @return The tag key.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The tag namespace.
     * 
     */
    public String namespace() {
        return this.namespace;
    }
    /**
     * @return The tag value.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTag defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private String namespace;
        private String value;
        public Builder() {}
        public Builder(GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTag defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.namespace = defaults.namespace;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder key(String key) {
            this.key = Objects.requireNonNull(key);
            return this;
        }
        @CustomType.Setter
        public Builder namespace(String namespace) {
            this.namespace = Objects.requireNonNull(namespace);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTag build() {
            final var o = new GetCustomTablesCustomTableCollectionItemSavedCustomTableGroupByTag();
            o.key = key;
            o.namespace = namespace;
            o.value = value;
            return o;
        }
    }
}