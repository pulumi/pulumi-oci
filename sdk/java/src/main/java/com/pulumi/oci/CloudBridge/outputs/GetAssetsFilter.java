// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudBridge.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAssetsFilter {
    /**
     * @return The tag name.
     * 
     */
    private String name;
    private @Nullable Boolean regex;
    private List<String> values;

    private GetAssetsFilter() {}
    /**
     * @return The tag name.
     * 
     */
    public String name() {
        return this.name;
    }
    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }
    public List<String> values() {
        return this.values;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAssetsFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private @Nullable Boolean regex;
        private List<String> values;
        public Builder() {}
        public Builder(GetAssetsFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.regex = defaults.regex;
    	      this.values = defaults.values;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetAssetsFilter", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder regex(@Nullable Boolean regex) {

            this.regex = regex;
            return this;
        }
        @CustomType.Setter
        public Builder values(List<String> values) {
            if (values == null) {
              throw new MissingRequiredPropertyException("GetAssetsFilter", "values");
            }
            this.values = values;
            return this;
        }
        public Builder values(String... values) {
            return values(List.of(values));
        }
        public GetAssetsFilter build() {
            final var _resultValue = new GetAssetsFilter();
            _resultValue.name = name;
            _resultValue.regex = regex;
            _resultValue.values = values;
            return _resultValue;
        }
    }
}
