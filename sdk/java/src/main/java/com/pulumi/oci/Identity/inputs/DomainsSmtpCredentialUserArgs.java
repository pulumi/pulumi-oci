// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsSmtpCredentialUserArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsSmtpCredentialUserArgs Empty = new DomainsSmtpCredentialUserArgs();

    /**
     * (Updatable) User display name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) User display name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * (Updatable) User name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) User name
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * User&#39;s ocid
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return User&#39;s ocid
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> ocid() {
        return Optional.ofNullable(this.ocid);
    }

    /**
     * (Updatable) The URI that corresponds to the user linked to this credential
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) The URI that corresponds to the user linked to this credential
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * User&#39;s id
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return User&#39;s id
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: immutable
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private DomainsSmtpCredentialUserArgs() {}

    private DomainsSmtpCredentialUserArgs(DomainsSmtpCredentialUserArgs $) {
        this.display = $.display;
        this.name = $.name;
        this.ocid = $.ocid;
        this.ref = $.ref;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsSmtpCredentialUserArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsSmtpCredentialUserArgs $;

        public Builder() {
            $ = new DomainsSmtpCredentialUserArgs();
        }

        public Builder(DomainsSmtpCredentialUserArgs defaults) {
            $ = new DomainsSmtpCredentialUserArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display (Updatable) User display name
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) User display name
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param name (Updatable) User name
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) User name
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param ocid User&#39;s ocid
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ocid(@Nullable Output<String> ocid) {
            $.ocid = ocid;
            return this;
        }

        /**
         * @param ocid User&#39;s ocid
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ocid(String ocid) {
            return ocid(Output.of(ocid));
        }

        /**
         * @param ref (Updatable) The URI that corresponds to the user linked to this credential
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) The URI that corresponds to the user linked to this credential
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param value User&#39;s id
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value User&#39;s id
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: immutable
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsSmtpCredentialUserArgs build() {
            return $;
        }
    }

}
