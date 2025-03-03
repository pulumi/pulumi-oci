// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDataMaskRulesFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetDataMaskRulesFilter Empty = new GetDataMaskRulesFilter();

    @Import(name="name", required=true)
    private String name;

    public String name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Boolean regex;

    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }

    /**
     * Types of targets
     * 
     */
    @Import(name="values", required=true)
    private List<String> values;

    /**
     * @return Types of targets
     * 
     */
    public List<String> values() {
        return this.values;
    }

    private GetDataMaskRulesFilter() {}

    private GetDataMaskRulesFilter(GetDataMaskRulesFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDataMaskRulesFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDataMaskRulesFilter $;

        public Builder() {
            $ = new GetDataMaskRulesFilter();
        }

        public Builder(GetDataMaskRulesFilter defaults) {
            $ = new GetDataMaskRulesFilter(Objects.requireNonNull(defaults));
        }

        public Builder name(String name) {
            $.name = name;
            return this;
        }

        public Builder regex(@Nullable Boolean regex) {
            $.regex = regex;
            return this;
        }

        /**
         * @param values Types of targets
         * 
         * @return builder
         * 
         */
        public Builder values(List<String> values) {
            $.values = values;
            return this;
        }

        /**
         * @param values Types of targets
         * 
         * @return builder
         * 
         */
        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetDataMaskRulesFilter build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetDataMaskRulesFilter", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetDataMaskRulesFilter", "values");
            }
            return $;
        }
    }

}
