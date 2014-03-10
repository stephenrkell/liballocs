/* We don't include anything, so that we can control which 
 * base types appear in our object code. We have to define 
 * dlsym() and RTLD_DEFAULT ourselves. */

extern void *dlsym (void *handle, const char *name);
extern int __libcrunch_check_init(void);
extern void __assert_fail (const char *__assertion, const char *__file,
                           unsigned int __line, const char *__function);

int main(void)
{
	/* We avoid using "signed short", and see if it's present 
	 * in our types object, given that we *do* use unsigned short. */
	__libcrunch_check_init();
	short unsigned int sshort_uniqtype_truncated = (short unsigned) (unsigned long) dlsym(
			0 /* RTLD_DEFAULT */, "__uniqtype__short_int");
	if (!sshort_uniqtype_truncated) __assert_fail("sshort_uniqtype_truncated", __FILE__, __LINE__, __func__);
	return 0;
}
