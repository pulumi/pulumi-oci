// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ManagementAgent.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagementAgentsFilter {
    /**
     * @return Name of the property
     * 
     */
    private String name;
    private @Nullable Boolean regex;
    /**
     * @return Values of the property
     * 
     */
    private List<String> values;

    private GetManagementAgentsFilter() {}
    /**
     * @return Name of the property
     * 
     */
    public String name() {
        return this.name;
    }
    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }
    /**
     * @return Values of the property
     * 
     */
    public List<String> values() {
        return this.values;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagementAgentsFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private @Nullable Boolean regex;
        private List<String> values;
        public Builder() {}
        public Builder(GetManagementAgentsFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.regex = defaults.regex;
    	      this.values = defaults.values;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetManagementAgentsFilter", "name");
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
              throw new MissingRequiredPropertyException("GetManagementAgentsFilter", "values");
            }
            this.values = values;
            return this;
        }
        public Builder values(String... values) {
            return values(List.of(values));
        }
        public GetManagementAgentsFilter build() {
            final var _resultValue = new GetManagementAgentsFilter();
            _resultValue.name = name;
            _resultValue.regex = regex;
            _resultValue.values = values;
            return _resultValue;
        }
    }
}
