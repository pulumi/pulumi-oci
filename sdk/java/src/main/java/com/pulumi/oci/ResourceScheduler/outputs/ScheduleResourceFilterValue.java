// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ResourceScheduler.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ScheduleResourceFilterValue {
    /**
     * @return This is the namespace of the defined tag.
     * 
     */
    private @Nullable String namespace;
    /**
     * @return This is the key of the defined tag.
     * 
     */
    private @Nullable String tagKey;
    /**
     * @return This is the lifecycle state value used for filtering.
     * 
     */
    private @Nullable String value;

    private ScheduleResourceFilterValue() {}
    /**
     * @return This is the namespace of the defined tag.
     * 
     */
    public Optional<String> namespace() {
        return Optional.ofNullable(this.namespace);
    }
    /**
     * @return This is the key of the defined tag.
     * 
     */
    public Optional<String> tagKey() {
        return Optional.ofNullable(this.tagKey);
    }
    /**
     * @return This is the lifecycle state value used for filtering.
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ScheduleResourceFilterValue defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String namespace;
        private @Nullable String tagKey;
        private @Nullable String value;
        public Builder() {}
        public Builder(ScheduleResourceFilterValue defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.namespace = defaults.namespace;
    	      this.tagKey = defaults.tagKey;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder namespace(@Nullable String namespace) {

            this.namespace = namespace;
            return this;
        }
        @CustomType.Setter
        public Builder tagKey(@Nullable String tagKey) {

            this.tagKey = tagKey;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {

            this.value = value;
            return this;
        }
        public ScheduleResourceFilterValue build() {
            final var _resultValue = new ScheduleResourceFilterValue();
            _resultValue.namespace = namespace;
            _resultValue.tagKey = tagKey;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
