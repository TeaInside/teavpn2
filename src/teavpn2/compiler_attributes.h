// SPDX-License-Identifier: GPL-2.0-only
/*
 * Thanks to the Linux Kernel
 * https://github.com/torvalds/linux/blob/a3b397b4fffb799d25658defafd962f0fb3e9fe0/include/linux/compiler_attributes.h
 *
 */
#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#ifndef __LINUX_COMPILER_ATTRIBUTES_H
#ifndef __LINUX_COMPILER_ATTRIBUTES_
#  define __LINUX_COMPILER_ATTRIBUTES_H
#endif

/*
 * The attributes in this file are unconditionally defined and they directly
 * map to compiler attribute(s), unless one of the compilers does not support
 * the attribute. In that case, __has_attribute is used to check for support
 * and the reason is stated in its comment ("Optional: ...").
 *
 * Any other "attributes" (i.e. those that depend on a configuration option,
 * on a compiler, on an architecture, on plugins, on other attributes...)
 * should be defined elsewhere (e.g. compiler_types.h or compiler-*.h).
 * The intention is to keep this file as simple as possible, as well as
 * compiler- and version-agnostic (e.g. avoiding GCC_VERSION checks).
 *
 * This file is meant to be sorted (by actual attribute name,
 * not by #ifndef identifier
#  define identifier). Use the __attribute__((__name__)) syntax
#endif
 * (i.e. with underscores) to avoid future collisions with other macros.
 * Provide links to the documentation of each supported compiler, if it exists.
 */

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-alias-function-attribute
 */
#ifndef __alias
#  define __alias(symbol)                 __attribute__((__alias__(#symbol)))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-aligned-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#index-aligned-type-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-aligned-variable-attribute
 */
#ifndef __aligned
#  define __aligned(x)                    __attribute__((__aligned__(x)))
#endif
#ifndef __aligned_largest
#  define __aligned_largest               __attribute__((__aligned__))
#endif

/*
 * Note: users of __always_inline currently do not write "inline" themselves,
 * which seems to be required by gcc to apply the attribute according
 * to its docs (and also "warning: always_inline function might not be
 * inlinable [-Wattributes]" is emitted).
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-always_005finline-function-attribute
 * clang: mentioned
 */
#ifndef __always_inline
#  define __always_inline                 inline __attribute__((__always_inline__))
#endif

/*
 * The second argument is optional (default 0), so we use a variadic macro
 * to make the shorthand.
 *
 * Beware: Do not apply this to functions which may return
 * ERR_PTRs. Also, it is probably unwise to apply it to functions
 * returning extra information in the low bits (but in that case the
 * compiler should see some alignment anyway, when the return value is
 * massaged by 'flags = ptr & 3; ptr &= ~3;').
 *
 * Optional: not supported by icc
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-assume_005faligned-function-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#assume-aligned
 */
#if __has_attribute(__assume_aligned__)
# define __assume_aligned(a, ...)       __attribute__((__assume_aligned__(a, ## __VA_ARGS__)))
#else
# define __assume_aligned(a, ...)
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-cold-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Label-Attributes.html#index-cold-label-attribute
 */
#ifndef __cold
#  define __cold                          __attribute__((__cold__))
#endif

/*
 * Note the long name.
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-const-function-attribute
 */
#ifndef __attribute_const__
#  define __attribute_const__             __attribute__((__const__))
#endif

/*
 * Optional: only supported since gcc >= 9
 * Optional: not supported by clang
 * Optional: not supported by icc
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-copy-function-attribute
 */
#if __has_attribute(__copy__)
# define __copy(symbol)                 __attribute__((__copy__(symbol)))
#else
# define __copy(symbol)
#endif

/*
 * Don't. Just don't. See commit 771c035372a0 ("deprecate the '__deprecated'
 * attribute warnings entirely and for good") for more information.
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-deprecated-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#index-deprecated-type-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-deprecated-variable-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Enumerator-Attributes.html#index-deprecated-enumerator-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#deprecated
 */
#ifndef __deprecate
#  define __deprecated
#endif

/*
 * Optional: only supported since gcc >= 5.1
 * Optional: not supported by clang
 * Optional: not supported by icc
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#index-designated_005finit-type-attribute
 */
#if __has_attribute(__designated_init__)
# define __designated_init              __attribute__((__designated_init__))
#else
# define __designated_init
#endif

/*
 * Optional: only supported since clang >= 14.0
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-error-function-attribute
 */
#if __has_attribute(__error__)
# define __compiletime_error(msg)       __attribute__((__error__(msg)))
#else
# define __compiletime_error(msg)
#endif

/*
 * Optional: not supported by clang
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-externally_005fvisible-function-attribute
 */
#if __has_attribute(__externally_visible__)
# define __visible                      __attribute__((__externally_visible__))
#else
# define __visible
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-format-function-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#format
 */
#ifndef __printf
#  define __printf(a, b)                  __attribute__((__format__(printf, a, b)))
#endif
#ifndef __scanf
#  define __scanf(a, b)                   __attribute__((__format__(scanf, a, b)))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-gnu_005finline-function-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#gnu-inline
 */
#ifndef __gnu_inline
#  define __gnu_inline                    __attribute__((__gnu_inline__))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-malloc-function-attribute
 */
#ifndef __malloc
#  define __malloc                        __attribute__((__malloc__))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#index-mode-type-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-mode-variable-attribute
 */
#ifndef __mode
#  define __mode(x)                       __attribute__((__mode__(x)))
#endif

/*
 * Optional: only supported since gcc >= 7
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/x86-Function-Attributes.html#index-no_005fcaller_005fsaved_005fregisters-function-attribute_002c-x86
 * clang: https://clang.llvm.org/docs/AttributeReference.html#no-caller-saved-registers
 */
#if __has_attribute(__no_caller_saved_registers__)
# define __no_caller_saved_registers	__attribute__((__no_caller_saved_registers__))
#else
# define __no_caller_saved_registers
#endif

/*
 * Optional: not supported by clang
 *
 *  gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-noclone-function-attribute
 */
#if __has_attribute(__noclone__)
# define __noclone                      __attribute__((__noclone__))
#else
# define __noclone
#endif

/*
 * Add the pseudo keyword 'fallthrough' so case statement blocks
 * must end with any of these keywords:
 *   break;
 *   fallthrough;
 *   continue;
 *   goto <label>;
 *   return [expression];
 *
 *  gcc: https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

/*
 * gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#Common-Function-Attributes
 * clang: https://clang.llvm.org/docs/AttributeReference.html#flatten
 */
# define __flatten			__attribute__((flatten))

/*
 * Note the missing underscores.
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-noinline-function-attribute
 * clang: mentioned
 */
#define   noinline                      __attribute__((__noinline__))

/*
 * Optional: only supported since gcc >= 8
 * Optional: not supported by clang
 * Optional: not supported by icc
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-nonstring-variable-attribute
 */
#if __has_attribute(__nonstring__)
# define __nonstring                    __attribute__((__nonstring__))
#else
# define __nonstring
#endif

/*
 * Optional: only supported since GCC >= 7.1, clang >= 13.0.
 *
 *      gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-no_005fprofile_005finstrument_005ffunction-function-attribute
 *    clang: https://clang.llvm.org/docs/AttributeReference.html#no-profile-instrument-function
 */
#if __has_attribute(__no_profile_instrument_function__)
# define __no_profile                  __attribute__((__no_profile_instrument_function__))
#else
# define __no_profile
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-noreturn-function-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#noreturn
 * clang: https://clang.llvm.org/docs/AttributeReference.html#id1
 */
#ifndef __noreturn
#  define __noreturn                      __attribute__((__noreturn__))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#index-packed-type-attribute
 * clang: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-packed-variable-attribute
 */
#ifndef __packed
#  define __packed                        __attribute__((__packed__))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-pure-function-attribute
 */
#ifndef __pure
#  define __pure                          __attribute__((__pure__))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-section-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-section-variable-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#section-declspec-allocate
 */
#ifndef __section
#  define __section(section)              __attribute__((__section__(section)))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-unused-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#index-unused-type-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-unused-variable-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Label-Attributes.html#index-unused-label-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#maybe-unused-unused
 */
#ifndef __always_unused
#  define __always_unused                 __attribute__((__unused__))
#endif
#ifndef __maybe_unused
#  define __maybe_unused                  __attribute__((__unused__))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-used-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-used-variable-attribute
 */
#ifndef __used
#  define __used                          __attribute__((__used__))
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-warn_005funused_005fresult-function-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#nodiscard-warn-unused-result
 */
#ifndef __must_check
#  define __must_check                    __attribute__((__warn_unused_result__))
#endif

/*
 * Optional: only supported since clang >= 14.0
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-warning-function-attribute
 */
#if __has_attribute(__warning__)
# define __compiletime_warning(msg)     __attribute__((__warning__(msg)))
#else
# define __compiletime_warning(msg)
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-weak-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-weak-variable-attribute
 */
#ifndef __weak
#  define __weak                          __attribute__((__weak__))
#endif

#endif /* __LINUX_COMPILER_ATTRIBUTES_H */

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif
