// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ScheduleQueryPropertiesGroupByTag {
    /**
     * @return The tag key.
     * 
     */
    private @Nullable String key;
    /**
     * @return The namespace needed to determine object storage bucket.
     * 
     */
    private @Nullable String namespace;
    /**
     * @return The tag value.
     * 
     */
    private @Nullable String value;

    private ScheduleQueryPropertiesGroupByTag() {}
    /**
     * @return The tag key.
     * 
     */
    public Optional<String> key() {
        return Optional.ofNullable(this.key);
    }
    /**
     * @return The namespace needed to determine object storage bucket.
     * 
     */
    public Optional<String> namespace() {
        return Optional.ofNullable(this.namespace);
    }
    /**
     * @return The tag value.
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ScheduleQueryPropertiesGroupByTag defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String key;
        private @Nullable String namespace;
        private @Nullable String value;
        public Builder() {}
        public Builder(ScheduleQueryPropertiesGroupByTag defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.namespace = defaults.namespace;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder key(@Nullable String key) {
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder namespace(@Nullable String namespace) {
            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {
            this.value = value;
            return this;
        }
        public ScheduleQueryPropertiesGroupByTag build() {
            final var o = new ScheduleQueryPropertiesGroupByTag();
            o.key = key;
            o.namespace = namespace;
            o.value = value;
            return o;
        }
    }
}