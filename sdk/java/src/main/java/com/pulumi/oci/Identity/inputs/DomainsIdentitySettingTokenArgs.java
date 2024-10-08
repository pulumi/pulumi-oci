// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsIdentitySettingTokenArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsIdentitySettingTokenArgs Empty = new DomainsIdentitySettingTokenArgs();

    /**
     * (Updatable) Indicates the number of minutes after which the token expires automatically.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    @Import(name="expiresAfter")
    private @Nullable Output<Integer> expiresAfter;

    /**
     * @return (Updatable) Indicates the number of minutes after which the token expires automatically.
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * multiValued: false
     * * mutability: readWrite
     * * required: false
     * * returned: default
     * * type: integer
     * * uniqueness: none
     * 
     */
    public Optional<Output<Integer>> expiresAfter() {
        return Optional.ofNullable(this.expiresAfter);
    }

    /**
     * (Updatable) The token type.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) The token type.
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * multiValued: false
     * * mutability: readWrite
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private DomainsIdentitySettingTokenArgs() {}

    private DomainsIdentitySettingTokenArgs(DomainsIdentitySettingTokenArgs $) {
        this.expiresAfter = $.expiresAfter;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsIdentitySettingTokenArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsIdentitySettingTokenArgs $;

        public Builder() {
            $ = new DomainsIdentitySettingTokenArgs();
        }

        public Builder(DomainsIdentitySettingTokenArgs defaults) {
            $ = new DomainsIdentitySettingTokenArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param expiresAfter (Updatable) Indicates the number of minutes after which the token expires automatically.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: integer
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder expiresAfter(@Nullable Output<Integer> expiresAfter) {
            $.expiresAfter = expiresAfter;
            return this;
        }

        /**
         * @param expiresAfter (Updatable) Indicates the number of minutes after which the token expires automatically.
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * multiValued: false
         * * mutability: readWrite
         * * required: false
         * * returned: default
         * * type: integer
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder expiresAfter(Integer expiresAfter) {
            return expiresAfter(Output.of(expiresAfter));
        }

        /**
         * @param type (Updatable) The token type.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The token type.
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * multiValued: false
         * * mutability: readWrite
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public DomainsIdentitySettingTokenArgs build() {
            if ($.type == null) {
                throw new MissingRequiredPropertyException("DomainsIdentitySettingTokenArgs", "type");
            }
            return $;
        }
    }

}
