// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDomainsOciConsoleSignOnPolicyConsentsFilter extends com.pulumi.resources.InvokeArgs {

    public static final GetDomainsOciConsoleSignOnPolicyConsentsFilter Empty = new GetDomainsOciConsoleSignOnPolicyConsentsFilter();

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

    @Import(name="values", required=true)
    private List<String> values;

    public List<String> values() {
        return this.values;
    }

    private GetDomainsOciConsoleSignOnPolicyConsentsFilter() {}

    private GetDomainsOciConsoleSignOnPolicyConsentsFilter(GetDomainsOciConsoleSignOnPolicyConsentsFilter $) {
        this.name = $.name;
        this.regex = $.regex;
        this.values = $.values;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDomainsOciConsoleSignOnPolicyConsentsFilter defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDomainsOciConsoleSignOnPolicyConsentsFilter $;

        public Builder() {
            $ = new GetDomainsOciConsoleSignOnPolicyConsentsFilter();
        }

        public Builder(GetDomainsOciConsoleSignOnPolicyConsentsFilter defaults) {
            $ = new GetDomainsOciConsoleSignOnPolicyConsentsFilter(Objects.requireNonNull(defaults));
        }

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

        public GetDomainsOciConsoleSignOnPolicyConsentsFilter build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("GetDomainsOciConsoleSignOnPolicyConsentsFilter", "name");
            }
            if ($.values == null) {
                throw new MissingRequiredPropertyException("GetDomainsOciConsoleSignOnPolicyConsentsFilter", "values");
            }
            return $;
        }
    }

}
