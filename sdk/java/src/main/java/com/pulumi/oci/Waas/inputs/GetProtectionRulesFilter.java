// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProtectionRulesFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetProtectionRulesFilter Empty = new GetProtectionRulesFilter();

    /**
     * The name of the protection rule.
     * 
     */
    @Import(name="name", required=true)
    private String name;

    /**
     * @return The name of the protection rule.
     * 
     */
    public String name() {
        return this.name;
    }

    @Import(name="regex")
    private @Nullable Boolean regex;

    public Optional<Boolean> regex() {
        return Optional.ofNullable(this.regex);
    }

    @Import(name="values", required=true)
    private List<String> values;

    public List<String> values() {
        return this.values;
    }

    private GetProtectionRulesFilter() {}

    private GetProtectionRulesFilter(GetProtectionRulesFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProtectionRulesFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProtectionRulesFilter $;

        public Builder() {
            $ = new GetProtectionRulesFilter();
        }

        public Builder(GetProtectionRulesFilter defaults) {
            $ = new GetProtectionRulesFilter(Objects.requireNonNull(defaults));
        }

        /**
         * @param name The name of the protection rule.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            $.name = name;
            return this;
        }

        public Builder regex(@Nullable Boolean regex) {
            $.regex = regex;
            return this;
        }

        public Builder values(List<String> values) {
            $.values = values;
            return this;
        }

        public Builder values(String... values) {
            return values(List.of(values));
        }

        public GetProtectionRulesFilter build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            $.values = Objects.requireNonNull($.values, "expected parameter 'values' to be non-null");
            return $;
        }
    }

}